constants = import_module("../../package_io/constants.star")
input_parser = import_module("../../package_io/input_parser.star")
node_metrics = import_module("../../node_metrics_info.star")
remote_signer_context = import_module("../remote_signer_context.star")
shared_utils = import_module("../../shared_utils/shared_utils.star")

# go-remotesigner signs for one validator client with the deposit CLI keystores
# the package generated for it; the validator client then holds no keys.
# Both containers mount their files at constants.REMOTE_SIGNER_MOUNTPOINT_ON_CLIENTS.
GO_REMOTESIGNER_FILES_MOUNTPOINT = constants.REMOTE_SIGNER_MOUNTPOINT_ON_CLIENTS

# The signer's files, besides the sign token (constants.REMOTE_SIGNER_AUTH_TOKEN_FILENAME)
GO_REMOTESIGNER_NETWORK_DIRNAME = "network"
GO_REMOTESIGNER_KEYSTORES_DIRNAME = "keystores"
GO_REMOTESIGNER_PASSWORD_FILENAME = "password.txt"
GO_REMOTESIGNER_TLS_CERT_FILEPATH = "tls/cert.pem"
GO_REMOTESIGNER_TLS_KEY_FILEPATH = "tls/key.pem"

# The image's data directory: the slashing-protection store (bbolt, on) and
# the admin token the signer generates
GO_REMOTESIGNER_DATA_DIRPATH = "/data"

# The image runs as its nonroot user, which must own the files it reads: the
# signer refuses secret files that their group or other users can read
GO_REMOTESIGNER_USER = "65532:65532"

GO_REMOTESIGNER_HTTP_PORT_NUM = 9000
GO_REMOTESIGNER_HTTP_PORT_ID = "http"
GO_REMOTESIGNER_METRICS_PORT_NUM = 9001
GO_REMOTESIGNER_METRICS_PORT_ID = "metrics"

METRICS_PATH = "/metrics"

# The API serves TLS only; the metrics listener is plain HTTP
GO_REMOTESIGNER_USED_PORTS = {
    GO_REMOTESIGNER_HTTP_PORT_ID: shared_utils.new_port_spec(
        GO_REMOTESIGNER_HTTP_PORT_NUM,
        shared_utils.TCP_PROTOCOL,
        shared_utils.HTTPS_APPLICATION_PROTOCOL,
    ),
    GO_REMOTESIGNER_METRICS_PORT_ID: shared_utils.new_port_spec(
        GO_REMOTESIGNER_METRICS_PORT_NUM,
        shared_utils.TCP_PROTOCOL,
        shared_utils.HTTP_APPLICATION_PROTOCOL,
    ),
}

# How long the signer may take to decrypt its keystores and open its store
GO_REMOTESIGNER_READY_TIMEOUT_SECONDS = 600

# Each key's RANDAO new-layer bucket refills one token per epoch. With fewer
# validators than this many times SLOTS_PER_EPOCH, honest proposals empty it,
# so the bucket is turned off
RANDAO_BUCKET_MIN_VALIDATORS_PER_SLOT = 4

VERBOSITY_LEVELS = {
    constants.GLOBAL_LOG_LEVEL.error: "ERROR",
    constants.GLOBAL_LOG_LEVEL.warn: "WARN",
    constants.GLOBAL_LOG_LEVEL.info: "INFO",
    constants.GLOBAL_LOG_LEVEL.debug: "DEBUG",
    constants.GLOBAL_LOG_LEVEL.trace: "TRACE",
}

# The min/max CPU/memory that the remote signer can use
MIN_CPU = 50
MAX_CPU = 300
MIN_MEMORY = 128
MAX_MEMORY = 1024


def launch(
    plan,
    launcher,
    service_name,
    image,
    participant,
    global_log_level,
    tolerations,
    node_selectors,
    port_publisher,
    remote_signer_index,
):
    log_level = input_parser.get_client_log_level_or_default(
        participant.vc_log_level, global_log_level, VERBOSITY_LEVELS
    )

    signer_files_artifact_uuid, vc_files_artifact_uuid = prepare_files(
        plan, launcher, service_name, participant.validator_count
    )

    config = get_config(
        participant=participant,
        image=image,
        service_name=service_name,
        vc_type=launcher.vc_type,
        signer_files_artifact_uuid=signer_files_artifact_uuid,
        log_level=log_level,
        randao_bucket_enabled=(
            launcher.network_validator_count
            >= RANDAO_BUCKET_MIN_VALIDATORS_PER_SLOT * launcher.slots_per_epoch
        ),
        tolerations=tolerations,
        node_selectors=node_selectors,
        port_publisher=port_publisher,
        remote_signer_index=remote_signer_index,
    )

    remote_signer_service = plan.add_service(service_name, config)

    # The validator client dials the service name, which the certificate is
    # issued for
    remote_signer_http_url = "https://{0}:{1}".format(
        service_name, GO_REMOTESIGNER_HTTP_PORT_NUM
    )
    wait_for_keys(
        plan,
        launcher.generator_image,
        service_name,
        remote_signer_http_url,
        vc_files_artifact_uuid,
    )

    remote_signer_metrics_port = remote_signer_service.ports[
        GO_REMOTESIGNER_METRICS_PORT_ID
    ]
    validator_metrics_url = "{0}:{1}".format(
        remote_signer_service.ip_address, remote_signer_metrics_port.number
    )
    remote_signer_node_metrics_info = node_metrics.new_node_metrics_info(
        service_name, METRICS_PATH, validator_metrics_url
    )

    return remote_signer_context.new_remote_signer_context(
        http_url=remote_signer_http_url,
        client_name=constants.REMOTE_SIGNER_TYPE.go_remotesigner,
        service_name=service_name,
        metrics_info=remote_signer_node_metrics_info,
        vc_files_artifact_uuid=vc_files_artifact_uuid,
    )


# Prepares two files artifacts with the generator image (sh, openssl, jq):
# - the signer's: the chain's config and genesis state, the validator client's
#   deposit CLI keystores (without the deposit data), the password they share,
#   the sign token, and a TLS certificate and key for the service name, owned
#   by the image's user (the genesis artifact's genesis.ssz is root's, 0600),
#   the secrets 0600;
# - the validator client's: the same token, its public keys (one per line)
#   and the CA that issued the signer's certificate.
# The token never appears in a command line, and the CA key never leaves
# this step.
def prepare_files(plan, launcher, service_name, validator_count):
    keystores_mountpoint = "/keystores"
    password_mountpoint = "/qrysm-password"
    keystores_dirpath = shared_utils.path_join(
        keystores_mountpoint,
        launcher.node_keystore_files.validator_keys_relative_dirpath,
    )
    password_filepath = shared_utils.path_join(
        password_mountpoint, launcher.qrysm_password_relative_filepath
    )

    signer = "/out/signer"
    vc = "/out/vc"
    signer_network = shared_utils.path_join(signer, GO_REMOTESIGNER_NETWORK_DIRNAME)
    signer_keystores = shared_utils.path_join(signer, GO_REMOTESIGNER_KEYSTORES_DIRNAME)
    signer_password = shared_utils.path_join(signer, GO_REMOTESIGNER_PASSWORD_FILENAME)
    signer_token = shared_utils.path_join(
        signer, constants.REMOTE_SIGNER_AUTH_TOKEN_FILENAME
    )
    signer_cert = shared_utils.path_join(signer, GO_REMOTESIGNER_TLS_CERT_FILEPATH)
    signer_key = shared_utils.path_join(signer, GO_REMOTESIGNER_TLS_KEY_FILEPATH)
    vc_token = shared_utils.path_join(vc, constants.REMOTE_SIGNER_AUTH_TOKEN_FILENAME)
    vc_key_file = shared_utils.path_join(vc, constants.REMOTE_SIGNER_KEY_FILENAME)
    vc_ca = shared_utils.path_join(vc, constants.REMOTE_SIGNER_TLS_CA_FILENAME)

    run = "\n".join(
        [
            "set -eu",
            "mkdir -p {0} {1} {2} {3}".format(
                signer_network, signer_keystores, shared_utils.path_dir(signer_cert), vc
            ),
            "cp {0}/config.yaml {0}/genesis.ssz {1}/".format(
                constants.GENESIS_DATA_MOUNTPOINT_ON_CLIENTS, signer_network
            ),
            "cp {0}/keystore-*.json {1}/".format(keystores_dirpath, signer_keystores),
            "cp {0} {1}".format(password_filepath, signer_password),
            "printf '0x%s\\n' \"$(openssl rand -hex 32)\" > {0}".format(signer_token),
            "cp {0} {1}".format(signer_token, vc_token),
            'jq -r \'.pubkey | ltrimstr("0x") | "0x" + ascii_downcase\' {0}/*.json | LC_ALL=C sort > {1}'.format(
                signer_keystores, vc_key_file
            ),
            'test "$(wc -l < {0})" -eq {1}'.format(vc_key_file, validator_count),
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj '/CN={0} CA' -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout /tmp/ca-key.pem -out {1}".format(
                service_name, vc_ca
            ),
            "openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN={0}' -keyout {1} -out /tmp/signer.csr".format(
                service_name, signer_key
            ),
            # Clients on the host reach the published port on the loopback address
            "printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=serverAuth\\nsubjectAltName=DNS:{0},DNS:localhost,IP:127.0.0.1\\n' > /tmp/signer.ext".format(
                service_name
            ),
            "openssl x509 -req -in /tmp/signer.csr -CA {0} -CAkey /tmp/ca-key.pem -set_serial 0x$(openssl rand -hex 16) -days 3650 -extfile /tmp/signer.ext -out {1}".format(
                vc_ca, signer_cert
            ),
            "openssl verify -CAfile {0} -verify_hostname {1} {2}".format(
                vc_ca, service_name, signer_cert
            ),
            "chown -R {0} {1}".format(GO_REMOTESIGNER_USER, signer),
            "chmod 0700 {0} {1} {2}".format(
                signer, signer_keystores, shared_utils.path_dir(signer_cert)
            ),
            "chmod 0600 {0} {1} {2}/* {3} {4} {5}".format(
                signer_password,
                signer_token,
                signer_keystores,
                signer_cert,
                signer_key,
                vc_token,
            ),
        ]
    )

    result = plan.run_sh(
        name="{0}-files".format(service_name),
        description="Preparing the keystores, sign token and TLS files of {0}".format(
            service_name
        ),
        image=launcher.generator_image,
        files={
            constants.GENESIS_DATA_MOUNTPOINT_ON_CLIENTS: launcher.el_cl_genesis_data.files_artifact_uuid,
            keystores_mountpoint: launcher.node_keystore_files.files_artifact_uuid,
            password_mountpoint: launcher.qrysm_password_artifact_uuid,
        },
        run=run,
        store=[
            StoreSpec(src=signer + "/", name="{0}-files".format(service_name)),
            StoreSpec(src=vc + "/", name="{0}-vc-files".format(service_name)),
        ],
    )

    return result.files_artifacts[0], result.files_artifacts[1]


# The API serves TLS only, which Kurtosis ready conditions do not speak, so a
# client with the validator client's files checks it the way the validator
# client will: /upcheck answers 200 once the keys are loaded and the store is
# open, and publicKeys must then list exactly the keys of the key file
def wait_for_keys(plan, image, service_name, http_url, vc_files_artifact_uuid):
    mountpoint = constants.REMOTE_SIGNER_MOUNTPOINT_ON_CLIENTS
    ca = shared_utils.path_join(mountpoint, constants.REMOTE_SIGNER_TLS_CA_FILENAME)
    token = shared_utils.path_join(
        mountpoint, constants.REMOTE_SIGNER_AUTH_TOKEN_FILENAME
    )
    key_file = shared_utils.path_join(mountpoint, constants.REMOTE_SIGNER_KEY_FILENAME)

    run = "\n".join(
        [
            "set -eu",
            "deadline=$(($(date +%s) + {0}))".format(
                GO_REMOTESIGNER_READY_TIMEOUT_SECONDS
            ),
            "until curl -fs -o /dev/null --max-time 5 --cacert {0} {1}/upcheck; do".format(
                ca, http_url
            ),
            '  if [ "$(date +%s)" -ge "$deadline" ]; then',
            "    echo '{0} did not load its keys within {1}s' >&2; exit 1".format(
                service_name, GO_REMOTESIGNER_READY_TIMEOUT_SECONDS
            ),
            "  fi",
            "  sleep 1",
            "done",
            "curl -fsS --max-time 60 --cacert {0} -H \"Authorization: Bearer $(cat {1})\" {2}/api/v1/consensus/publicKeys | jq -r '.[]' | LC_ALL=C sort > /tmp/served-keys.txt".format(
                ca, token, http_url
            ),
            "if ! cmp -s /tmp/served-keys.txt {0}; then".format(key_file),
            '  echo "{0} serves $(wc -l < /tmp/served-keys.txt) keys, not the $(wc -l < {1}) of its validator client" >&2; exit 1'.format(
                service_name, key_file
            ),
            "fi",
        ]
    )

    plan.run_sh(
        name="{0}-ready".format(service_name),
        description="Waiting for {0} to load its keys".format(service_name),
        image=image,
        files={mountpoint: vc_files_artifact_uuid},
        run=run,
        wait="{0}s".format(GO_REMOTESIGNER_READY_TIMEOUT_SECONDS + 60),
    )


def get_config(
    participant,
    image,
    service_name,
    vc_type,
    signer_files_artifact_uuid,
    log_level,
    randao_bucket_enabled,
    tolerations,
    node_selectors,
    port_publisher,
    remote_signer_index,
):
    # Global flags, then the consensus command and its flags. The image's
    # entrypoint sets some of these global flags already; the last value wins.
    cmd = [
        "--data-path=" + GO_REMOTESIGNER_DATA_DIRPATH,
        "--http-listen-host=0.0.0.0",
        "--http-listen-port={0}".format(GO_REMOTESIGNER_HTTP_PORT_NUM),
        # The names clients connect with: the validator client dials the
        # service name, clients on the host the published port
        "--http-host-allowlist={0},localhost,127.0.0.1".format(service_name),
        "--http-auth-token-file="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT,
            constants.REMOTE_SIGNER_AUTH_TOKEN_FILENAME,
        ),
        "--tls-cert-file="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT, GO_REMOTESIGNER_TLS_CERT_FILEPATH
        ),
        "--tls-key-file="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT, GO_REMOTESIGNER_TLS_KEY_FILEPATH
        ),
        "--metrics-enabled=true",
        # Prometheus scrapes the service by its IP address
        "--metrics-host-allowlist=*",
        "--metrics-host=0.0.0.0",
        "--metrics-port={0}".format(GO_REMOTESIGNER_METRICS_PORT_NUM),
        "--logging=" + log_level,
        "consensus",
        "--network="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT,
            GO_REMOTESIGNER_NETWORK_DIRNAME,
            "config.yaml",
        ),
        # The genesis time and the genesis validators root, which a listener
        # beyond loopback must know
        "--network-genesis-state="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT,
            GO_REMOTESIGNER_NETWORK_DIRNAME,
            "genesis.ssz",
        ),
        "--keystores-path="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT, GO_REMOTESIGNER_KEYSTORES_DIRNAME
        ),
        "--keystores-password-file="
        + shared_utils.path_join(
            GO_REMOTESIGNER_FILES_MOUNTPOINT, GO_REMOTESIGNER_PASSWORD_FILENAME
        ),
        # Slashing protection stays on, in the bbolt store under --data-path
    ]

    if not randao_bucket_enabled:
        cmd.append("--randao-new-layer-refill-epochs=0")

    if len(participant.remote_signer_extra_params) > 0:
        # this is a repeated<proto type>, we convert it into Starlark
        cmd.extend([param for param in participant.remote_signer_extra_params])

    files = {
        GO_REMOTESIGNER_FILES_MOUNTPOINT: signer_files_artifact_uuid,
    }

    public_ports = {}
    if port_publisher.remote_signer_enabled:
        public_ports_for_component = shared_utils.get_public_ports_for_component(
            "remote-signer", port_publisher, remote_signer_index
        )
        public_ports = {
            GO_REMOTESIGNER_HTTP_PORT_ID: shared_utils.new_port_spec(
                public_ports_for_component[0],
                shared_utils.TCP_PROTOCOL,
                shared_utils.HTTPS_APPLICATION_PROTOCOL,
            ),
            GO_REMOTESIGNER_METRICS_PORT_ID: shared_utils.new_port_spec(
                public_ports_for_component[1],
                shared_utils.TCP_PROTOCOL,
                shared_utils.HTTP_APPLICATION_PROTOCOL,
            ),
        }

    ports = {}
    ports.update(GO_REMOTESIGNER_USED_PORTS)

    config_args = {
        "image": image,
        "ports": ports,
        "public_ports": public_ports,
        "cmd": cmd,
        "files": files,
        "env_vars": participant.remote_signer_extra_env_vars,
        "labels": shared_utils.label_maker(
            client=constants.REMOTE_SIGNER_TYPE.go_remotesigner,
            client_type=constants.CLIENT_TYPES.remote_signer,
            image=image,
            connected_client=vc_type,
            extra_labels=participant.remote_signer_extra_labels,
            supernode=participant.supernode,
        ),
        "tolerations": tolerations,
        "node_selectors": node_selectors,
    }

    if participant.remote_signer_min_cpu > 0:
        config_args["min_cpu"] = participant.remote_signer_min_cpu
    if participant.remote_signer_max_cpu > 0:
        config_args["max_cpu"] = participant.remote_signer_max_cpu
    if participant.remote_signer_min_mem > 0:
        config_args["min_memory"] = participant.remote_signer_min_mem
    if participant.remote_signer_max_mem > 0:
        config_args["max_memory"] = participant.remote_signer_max_mem

    return ServiceConfig(**config_args)


def new_go_remotesigner_launcher(
    el_cl_genesis_data,
    vc_type,
    node_keystore_files,
    qrysm_password_artifact_uuid,
    qrysm_password_relative_filepath,
    generator_image,
    network_validator_count,
    slots_per_epoch,
):
    return struct(
        el_cl_genesis_data=el_cl_genesis_data,
        vc_type=vc_type,
        node_keystore_files=node_keystore_files,
        qrysm_password_artifact_uuid=qrysm_password_artifact_uuid,
        qrysm_password_relative_filepath=qrysm_password_relative_filepath,
        # Has sh, openssl, jq and curl: prepares the files and checks readiness
        generator_image=generator_image,
        # Validators of the whole network at genesis
        network_validator_count=network_validator_count,
        slots_per_epoch=slots_per_epoch,
    )
