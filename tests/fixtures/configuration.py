import pathlib

current_dir = pathlib.Path(__file__).parent.resolve()
username = 'dummy_user'
with open(pathlib.Path(current_dir, 'private.pem')) as key_file:
    private_key = key_file.read()

with open(pathlib.Path(current_dir, 'private_invalid.pem')) as key_file:
    invalid_private_key = key_file.read()

with open(pathlib.Path(current_dir, 'garbage.pem')) as key_file:
    garbage_private_key = key_file.read()
