#!/usr/bin/env python
from dotenv import load_dotenv
from argparse import ArgumentParser

from shutil import rmtree, copyfile
from os import uname, makedirs, path, chmod, environ
from subprocess import call, DEVNULL
from logging import Logger, Formatter, StreamHandler, DEBUG, INFO, WARNING, ERROR, getLogger

OUTPUT_DIRECTORY = 'secrets'
DEFAULT_HOSTNAME = f'{uname()[1]}.local'
DEFAULT_DAYS = 18250
DEFAULT_KEY_LENGTH_BITS = 2048
DESTINATION_MOSQUITTO_SECRETS_DIR = 'mosquitto/certs'
DESTINATION_MOSQUITTO_CONFIGURATION_DIR = 'mosquitto/conf.d'

HOSTNAME = ""
KEY_LENGTH_BITS = 0
DAYS = 0

LOGGER: Logger


class VT100Formatter(Formatter):

    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    format = "%(asctime)s [%(name)s][%(levelname)s] %(message)s"

    FORMATS = {
        INFO: green + format + reset,
        WARNING: yellow + format + reset,
        ERROR: red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = Formatter(log_fmt)
        return formatter.format(record)


def initialize_logging(name):
    global LOGGER
    LOGGER = getLogger(name)
    LOGGER.setLevel(INFO)
    ch = StreamHandler()
    ch.setLevel(DEBUG)
    ch.setFormatter(VT100Formatter())
    LOGGER.addHandler(ch)


def I(text):
    LOGGER.info(text)


def W(text):
    LOGGER.warning(text)


def E(text):
    LOGGER.error(text)


def get_full_path_of(relative_path: str) -> str:
    file_path = path.realpath(__file__)
    directory_path = path.dirname(file_path)
    return path.join(directory_path, relative_path)


def get_full_path_of_output_directory() -> str:
    return get_full_path_of(OUTPUT_DIRECTORY)


def get_subject_organisation_for_ca() -> str:
    return environ['X509_SUBJECT_ORGANISATION_CA']


def get_subject_organisation_for_broker() -> str:
    return environ['X509_SUBJECT_ORGANISATION_BROKER']


def get_subject_organisation_for_endpoint() -> str:
    return environ['X509_SUBJECT_ORGANISATION_ENDPOINT']


def get_subject_for(organisation: str, host: str) -> str:
    subject = [
        f"/C={environ['X509_SUBJECT_COUNTRY']}",
        f"/ST={environ['X509_SUBJECT_STATE']}",
        f"/L={environ['X509_SUBJECT_LOCATION']}",
        f"/O={organisation}",
        f"/CN={host}"
    ]
    return "".join(subject)


def get_cert_file_path(name: str) -> str:
    return path.join(get_full_path_of_output_directory(), f"{name}.crt")


def get_csr_file_path(name: str) -> str:
    return path.join(get_full_path_of_output_directory(), f"{name}.csr")


def get_key_file_path(name: str) -> str:
    return path.join(get_full_path_of_output_directory(), f"{name}.key")


def get_ca_cert_file_path() -> str:
    return get_cert_file_path('ca')


def get_ca_key_file_path() -> str:
    return get_key_file_path('ca')


def get_broker_cert_file_path() -> str:
    return get_cert_file_path('broker')


def get_broker_key_file_path() -> str:
    return get_key_file_path('broker')


def get_broker_csr_file_path() -> str:
    return get_csr_file_path('broker')


def generate_key_for(file_path: str) -> None:
    call(
        f'openssl genrsa -out {file_path} {DEFAULT_KEY_LENGTH_BITS}', shell=True, stderr=DEVNULL)


def generate_ca_secrets() -> None:
    I("Generate CA secrets")
    subject = f"-subj {get_subject_for(get_subject_organisation_for_ca(), HOSTNAME)}"
    generate_key_for(get_ca_key_file_path())
    call(
        f'openssl req -new -x509 -days {DAYS} -key {get_ca_key_file_path()} -out {get_ca_cert_file_path()} {subject}', shell=True)
    chmod(get_ca_key_file_path(), 0o644)
    chmod(get_ca_cert_file_path(), 0o644)


def generate_node_secrets(node_name: str, node_organisation: str, node_host_name: str) -> None:
    I(f"Generate {node_name} secrets")
    node_key_file = get_key_file_path(node_name)
    node_csr_file = get_csr_file_path(node_name)
    node_cert_file = get_cert_file_path(node_name)
    subject = f"-subj {get_subject_for(node_organisation, node_host_name)}"
    generate_key_for(node_key_file)
    call(
        f"openssl req -new -out {node_csr_file} -key {node_key_file} {subject}", shell=True)
    call(
        f"openssl x509 -req -in {node_csr_file} -CA {get_ca_cert_file_path()} -CAkey {get_ca_key_file_path()} -CAcreateserial -out {node_cert_file} -days {DAYS}", shell=True, stderr=DEVNULL)
    chmod(node_key_file, 0o644)
    chmod(node_cert_file, 0o644)


def generate_broker_secrets() -> None:
    generate_node_secrets(
        'broker', get_subject_organisation_for_broker(), HOSTNAME)


def parse_arguments():
    global HOSTNAME
    global DAYS
    global KEY_LENGTH_BITS
    parser = ArgumentParser()
    parser.add_argument(
        '--ca', help='Generate CA secrets (and the broker as well)', action='store_true')
    parser.add_argument(
        '--broker', help='Generate Broker secrets', action='store_true')
    parser.add_argument('--endpoint', help='Generate endpoint secrets')
    parser.add_argument(
        '--batch', help='Generate endpoints secrets from a list file')
    parser.add_argument(
        '--host', help=f"Set the broker host name to be stored in broker certificate (dafaults to {DEFAULT_HOSTNAME})")
    parser.add_argument('--days', help=f'Set the days secrets should be valid for (defaults to {DEFAULT_DAYS} days)',
                        default=DEFAULT_DAYS)
    parser.add_argument('--bits', help=f"Define key length in bits (defaults to {DEFAULT_KEY_LENGTH_BITS})",
                        default=DEFAULT_KEY_LENGTH_BITS)
    parser.add_argument(
        '--mosquitto', help='Copy secrets and generate mosquitto configuration to defined destination path')
    arguments = parser.parse_args()
    KEY_LENGTH_BITS = arguments.bits
    DAYS = arguments.days
    HOSTNAME = arguments.host
    return arguments


def ca_secrets_do_exist() -> bool:
    return path.exists(get_ca_cert_file_path()) and path.exists(get_ca_key_file_path())


def broker_secrets_do_exist() -> bool:
    return path.exists(get_broker_cert_file_path()) and path.exists(get_broker_key_file_path()) and path.exists(get_broker_csr_file_path())


def copy_file_to_destination(file_source_path: str, destination_directory: str) -> None:
    file_name = path.basename(file_source_path)
    destination_file_path = path.join(destination_directory, file_name)
    copyfile(file_source_path, destination_file_path)
    return destination_file_path


def copy_secrets_and_generate_configuration(destination_path: str) -> None:
    full_destination_path = get_full_path_of(destination_path)
    full_destination_secrets_path = path.join(
        full_destination_path, DESTINATION_MOSQUITTO_SECRETS_DIR)
    full_destination_secrets_path = path.realpath(
        full_destination_secrets_path)
    rmtree(full_destination_secrets_path, ignore_errors=True)
    makedirs(full_destination_secrets_path, exist_ok=True)
    destination_ca_cert_file_path = copy_file_to_destination(
        get_ca_cert_file_path(), full_destination_secrets_path)
    destination_broker_cert_file_path = copy_file_to_destination(
        get_broker_cert_file_path(), full_destination_secrets_path)
    destination_broker_key_file_path = copy_file_to_destination(
        get_broker_key_file_path(), full_destination_secrets_path)
    configuration = [
        "listener 8883",
        "tls_version tlsv1.3",
        f"cafile {destination_ca_cert_file_path}",
        f"keyfile {destination_broker_key_file_path}",
        f"certfile {destination_broker_cert_file_path}",
        "require_certificate true",
        "use_identity_as_username true",
        "use_username_as_clientid true"
    ]
    full_destination_configuration_path = path.join(
        full_destination_path, DESTINATION_MOSQUITTO_CONFIGURATION_DIR)
    full_destination_configuration_path = path.realpath(
        full_destination_configuration_path)
    rmtree(full_destination_configuration_path, ignore_errors=True)
    makedirs(full_destination_configuration_path, exist_ok=True)
    with open(path.join(full_destination_configuration_path, 'mosquitto.conf'), 'w') as config_file:
        config_file.write("\n".join(configuration))


def main():
    load_dotenv()
    initialize_logging('generate-secrets')
    args = parse_arguments()
    if not ca_secrets_do_exist() or args.ca:
        I("Clearing output directory")
        rmtree(get_full_path_of_output_directory(), ignore_errors=True)
        makedirs(get_full_path_of_output_directory())
        generate_ca_secrets()
    if not broker_secrets_do_exist() or args.broker:
        generate_broker_secrets()
    if args.endpoint:
        generate_node_secrets(
            args.endpoint, get_subject_organisation_for_endpoint(), args.endpoint)
    if args.batch:
        with open(args.batch) as batch_file:
            for line in batch_file:
                endpoint = line.strip()
                generate_node_secrets(
                    endpoint, get_subject_organisation_for_endpoint(), endpoint)
    if args.mosquitto:
        copy_secrets_and_generate_configuration(args.mosquitto)


if __name__ == "__main__":
    main()
