# One of these will be created per node we're trying to start
def new_keystore_files(
    files_artifact_uuid,
    qrysm_relative_dirpath,
    validator_keys_relative_dirpath=None,
):
    return struct(
        files_artifact_uuid=files_artifact_uuid,
        # ------------ All directories below are relative to the root of the files artifact ----------------
        qrysm_relative_dirpath=qrysm_relative_dirpath,
        # The deposit CLI keystores (keystore-*.json), all encrypted with the qrysm
        # password; None when the keystores were generated without the deposit CLI
        validator_keys_relative_dirpath=validator_keys_relative_dirpath,
    )
