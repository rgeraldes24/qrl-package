go_remotesigner = import_module("./go_remotesigner/go_remotesigner_launcher.star")
clef = import_module("./clef/clef_launcher.star")

constants = import_module("../package_io/constants.star")
input_parser = import_module("../package_io/input_parser.star")

def launch(
    plan,
    service_name,
    remote_signer_type,
    image,
    full_name,
    vc_type,
    el_type,
    clef_files,
    participant,
    global_tolerations,
    node_selectors,
    port_publisher,
    remote_signer_index,
    network_id,
    global_log_level,
    el_cl_genesis_data=None,
    node_keystore_files=None,
    qrysm_password_artifact_uuid=None,
    qrysm_password_relative_filepath=None,
    generator_image=None,
    network_validator_count=0,
    slots_per_epoch=0,
):
    plan.print("Launching remote signer")

    rs_launchers = {
        constants.REMOTE_SIGNER_TYPE.clef: {
            "launcher": clef.new_clef_launcher(
                network_id,
                el_type,
                clef_files=clef_files,
            ),
            "launch_method": clef.launch,
        },
        constants.REMOTE_SIGNER_TYPE.go_remotesigner: {
            "launcher": go_remotesigner.new_go_remotesigner_launcher(
                el_cl_genesis_data=el_cl_genesis_data,
                vc_type=vc_type,
                node_keystore_files=node_keystore_files,
                qrysm_password_artifact_uuid=qrysm_password_artifact_uuid,
                qrysm_password_relative_filepath=qrysm_password_relative_filepath,
                generator_image=generator_image,
                network_validator_count=network_validator_count,
                slots_per_epoch=slots_per_epoch,
            ),
            "launch_method": go_remotesigner.launch,
        },
    }

    tolerations = input_parser.get_client_tolerations(
        participant.remote_signer_tolerations,
        participant.tolerations,
        global_tolerations,
    )

    if remote_signer_type not in rs_launchers:
        fail(
            "Unsupported launcher '{0}', need one of '{1}'".format(
                remote_signer_type, ",".join(rs_launchers.keys())
            )
        )

    rs_launcher, launch_method = (
        rs_launchers[remote_signer_type]["launcher"],
        rs_launchers[remote_signer_type]["launch_method"],
    )

    rs_context = launch_method(
        plan,
        rs_launcher,
        service_name,
        image,
        participant,
        global_log_level,
        tolerations,
        node_selectors,
        port_publisher,
        remote_signer_index,
    )

    return rs_context
    