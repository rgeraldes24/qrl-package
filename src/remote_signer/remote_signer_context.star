def new_remote_signer_context(
    http_url,
    client_name,
    service_name,
    metrics_info,
    vc_files_artifact_uuid=None,
):
    return struct(
        http_url=http_url,
        client_name=client_name,
        service_name=service_name,
        metrics_info=metrics_info,
        # The files a validator client signs through this remote signer with,
        # mounted at constants.REMOTE_SIGNER_MOUNTPOINT_ON_CLIENTS; None for
        # remote signers of the execution clients
        vc_files_artifact_uuid=vc_files_artifact_uuid,
    )
