#!/usr/bin/env python3
"""Local certificate authority manager
"""
import os
import shutil
import json
from prompt_toolkit import prompt
from prompt_toolkit import shortcuts
from prompt_toolkit.completion import WordCompleter

# Config file pattern for certificate authority
RAW_CONFIG_FILE = """
[ ca ]
default_ca              = local_ca

[ local_ca ]
dir                     = TARGET_FOLDER
database                = $dir/index.txt
new_certs_dir           = $dir/signedcerts

certificate             = $dir/cacert.pem
serial                  = $dir/serial
private_key             = $dir/private/cakey.pem

default_days            = 3650
default_crl_days        = 365
default_md              = sha256

policy                  = local_ca_policy
x509_extensions         = local_ca_extensions

copy_extensions         = copy

[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn
copy_extensions = copy

[ local_ca_policy ]
commonName              = supplied
stateOrProvinceName     = supplied
countryName             = supplied
emailAddress            = supplied
organizationName        = supplied
organizationalUnitName  = supplied

[ local_ca_extensions ]
basicConstraints        = CA:FALSE

[ req ]
default_bits            = 2048
default_keyfile         = TARGET_FOLDER/private/cakey.pem
prompt                  = no
distinguished_name      = root_ca_distinguished_name
x509_extensions         = root_ca_extensions

[ root_ca_distinguished_name ]
commonName              = COMMON_NAME
stateOrProvinceName     = STATE
countryName             = COUNTRY
emailAddress            = EMAIL
organizationName        = ORGANIZATION
organizationalUnitName  = ORGANIZATION_UNIT_NAME

[ root_ca_extensions ]
basicConstraints        = critical,CA:true
subjectAltName          = @alt_names

[ alt_names ]
DNS.1 = *.DOMAIN
DNS.2 = DOMAIN
"""

# Config file pattern for server
RAW_SERVER_CONFIG_FILE = """
[ req ]
prompt                  = no
distinguished_name      = server_distinguished_name
req_extensions          = req_ext

[ server_distinguished_name ]
commonName              = SERVER_NAME.DOMAIN
stateOrProvinceName     = STATE
countryName             = COUNTRY
emailAddress            = EMAIL
organizationName        = ORGANIZATION
organizationalUnitName  = ORGANIZATION_UNIT_NAME

[ req_ext ]
basicConstraints        = CA:FALSE
keyUsage                = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName          = @alt_names

[ alt_names ]
DNS.0                   = localhost
DNS.1                   = SERVER_NAME.DOMAIN
DNS.2                   = SERVER_NAME
DNS.3                   = SERVER_IP
"""

class Manager:
    """Certificate authority manager
    """
    #pylint: disable=line-too-long, no-self-use
    # Shell loop
    loop = True
    # List of allowed commands
    commands_list = {}
    # List of certificate authority
    ca_list = []
    # Selected domain data
    selected_domain = None

    def __init__(self):
        """Init commands list
        """
        self.commands_list = {
            'create': self.create_ca,
            'quit': self.quit,
            'exit': self.quit,
            'list': self.show_list,
            'help': self.show_help,
            'select': self.select,
            'add': self.add_server
        }

    def create_ca(self):
        """Create certificate authority
        """
        domain = prompt('Domain : ', bottom_toolbar="Type the domain")
        target_folder = domain.replace('.', '-')
        target_folder = prompt('Target folder : ',
                               default=target_folder,
                               bottom_toolbar="Type the folder where data will be store")
        if os.path.exists(target_folder):
            confirm = shortcuts.confirm('Folder ' + target_folder + ' already exists. Overwrite it ?',
                                        suffix=' y/N ')
            if confirm:
                shutil.rmtree(target_folder)
            else:
                return
        os.mkdir(target_folder)
        os.mkdir(target_folder + os.sep + 'private')
        # Add / at the end
        target_folder = target_folder + os.sep
        # Prepare config file
        informations = self.get_ca_informations()
        config_content = RAW_CONFIG_FILE.replace('TARGET_FOLDER', os.getcwd())
        config_content = config_content.replace('COMMON_NAME', informations['common_name'])
        config_content = config_content.replace('STATE', informations['state'])
        config_content = config_content.replace('COUNTRY', informations['country'])
        config_content = config_content.replace('EMAIL', informations['email'])
        config_content = config_content.replace('ORGANIZATION_UNIT_NAME', informations['organization_unit_name'])
        config_content = config_content.replace('ORGANIZATION', informations['organization'])
        config_content = config_content.replace('DOMAIN', domain)
        with open(target_folder + 'ca_config.cnf', 'w') as config_file:
            config_file.write(config_content)
        # Create certificate authority
        print('openssl req -x509 -new -nodes -key ' + target_folder + 'RootCA.key -sha256 -days 1825 -out ' + target_folder + 'RootCA.pem')
        print('>>> Generate private key')
        os.system('openssl genrsa -des3 -out ' + target_folder + 'RootCA.key 4096')
        print('>>> Generate root certificate')
        os.system('openssl req -x509 -new -nodes -config ' + target_folder + 'ca_config.cnf -key ' + target_folder + 'RootCA.key -sha256 -days 1825 -out ' + target_folder + 'RootCA.pem')
        informations['domain'] = domain
        informations['path'] = target_folder
        # Write data
        with open(target_folder + 'data.json', 'w') as json_file:
            json.dump(informations, json_file)

    def get_ca_informations(self):
        """Ask user for certificate authority
        :return: Certificate authority needed data
        :rtype:  dict
        """
        informations = {}
        informations['common_name'] = prompt('Common name : ', bottom_toolbar="Full name of the domain")
        informations['state'] = prompt('State : ', bottom_toolbar="State")
        informations['country'] = prompt('Country : ', bottom_toolbar="Country ISO Code (2 letters)")
        informations['email'] = prompt('Email : ', bottom_toolbar="Contact email")
        informations['organization'] = prompt('Organization : ', bottom_toolbar="Name of the organization")
        informations['organization_unit_name'] = prompt('Organizational unit name : ', bottom_toolbar="Department of the organization")
        return informations

    def add_server(self):
        """Add server certificate
        """
        if self.selected_domain is None:
            print('No certificate authority selected')
        else:
            server_name = prompt('Server name : ', bottom_toolbar="Name of the server without domain")
            server_ip = prompt('IP : ', bottom_toolbar="Server IP")
            server_config = RAW_SERVER_CONFIG_FILE.replace('SERVER_NAME', server_name)
            server_config = server_config.replace('SERVER_IP', server_ip)
            server_config = server_config.replace('DOMAIN', self.selected_domain['domain'])
            server_config = server_config.replace('COMMON_NAME', self.selected_domain['common_name'])
            server_config = server_config.replace('STATE', self.selected_domain['state'])
            server_config = server_config.replace('COUNTRY', self.selected_domain['country'])
            server_config = server_config.replace('EMAIL', self.selected_domain['email'])
            server_config = server_config.replace('ORGANIZATION_UNIT_NAME', self.selected_domain['organization_unit_name'])
            server_config = server_config.replace('ORGANIZATION', self.selected_domain['organization'])
            with open('tmp.cnf', 'w') as config_file:
                config_file.write(server_config)
            target_folder = self.selected_domain['path']
            os.system('openssl genrsa -out ' + target_folder + server_name + '.key 4096')
            os.system('openssl req -new -sha256 -key ' + target_folder + server_name + '.key -out ' + target_folder + server_name + '.csr -config tmp.cnf')
            os.system('openssl x509 -req -in ' + target_folder + server_name + '.csr -CA ' + target_folder + 'RootCA.pem -CAkey ' + target_folder + 'RootCA.key -CAcreateserial -out ' + target_folder + server_name + '.crt -extensions req_ext -extfile tmp.cnf -days 1825 -sha256')
            os.system('cat ' + target_folder + server_name + '.crt ' + target_folder + server_name + '.key > ' + target_folder + server_name + '.pem ')
            os.remove('tmp.cnf')

    def show_help(self):
        """Show user help
        """
        print(' - create : Create certificate authority')
        print(' - select : Select an existing certificate authority')
        print(' - add : Generate a server certificate to selected certificate authority')
        print(' - list : List existing certificate authority')
        print(' - help : Show this message')

    def show_list(self):
        """Show created certificates authority
        """
        self.read_ca_list()
        for ca_data in self.ca_list:
            print(ca_data['domain'])

    def select(self):
        """Select certificate authority
        """
        self.read_ca_list()
        for index, ca_item in enumerate(self.ca_list):
            print(str(index + 1) + '. ' + ca_item['domain'])
        print('0. cancel')
        choice = prompt('Choice : ', bottom_toolbar="Type the number of the domain to select")
        try:
            choice = int(choice) - 1
            if 0 <= choice < len(self.ca_list):
                self.selected_domain = self.ca_list[choice]
                print('Domain ' + self.selected_domain['domain'] + ' selected.')
        except ValueError:
            print('Bad value')

    def read_ca_list(self):
        """Get data of certificate authority
        Store in ca_list
        """
        self.ca_list = []
        for item in os.listdir('.'):
            if os.path.isdir(item):
                data_file = item + os.sep + 'data.json'
                if os.path.exists(data_file):
                    with open(data_file, 'r') as json_file:
                        self.ca_list.append(json.load(json_file))

    def quit(self):
        """Quit manager
        """
        self.loop = False

    def start(self):
        """Start loop
        """
        commands_completer = WordCompleter(self.commands_list.keys())
        while self.loop:
            user_prompt = prompt('> ', completer=commands_completer, bottom_toolbar="Select a command. Type help for list of commands")
            user_prompt = user_prompt.strip()
            if user_prompt in self.commands_list:
                self.commands_list[user_prompt]()
            else:
                print(user_prompt + ' is not recognized. Use help.')

# Entry point
if __name__ == '__main__':
    MANAGER = Manager()
    try:
        MANAGER.start()
    except KeyboardInterrupt:
        pass
