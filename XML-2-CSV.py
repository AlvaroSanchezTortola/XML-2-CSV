import xml.etree.ElementTree as ET, csv

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def XMLtoCSV(input_xml, output_csv, debug=True):
    ''' Function to convert a XML input file from airodump-ng-1.0 to a 
        CSV file (intended for Report parsing)

        ARGS: XML file path from airodump-ng
              Output CSV file path
              debug flag
    '''
    tree = ET.parse(input_xml)
    root = tree.getroot()

    file = open(output_csv, 'w')
    csvwriter = csv.writer(file)
    csvwriter.writerow(['#','Type','ESSID','BSSID','Channel','Cloaked','Packets','# Connected clients','Encryption','Last Time'])
    for i in root.findall('wireless-network'):
        row = []
        load = lambda _: row.append(_) if _ is not None else row.append('')
        ''' lambda function load for writing empty string to array if XML tag doesnt exist
        '''
        row.append(i.attrib['number'])
        row.append(i.attrib['type'])
        try:
            load(i.find('SSID').find('essid').text)
        except Exception as e:
            load(None)
        row.append(i.find('BSSID').text)
        row.append(i.find('channel').text)
        try:
            load(i.find('SSID').find('essid').attrib['cloaked'])
        except Exception as e:
            load(None)
        row.append(i.find('packets').find('total').text)
        load(len([j.attrib['number'] for j in i.iter('wireless-client')]))
        try:
            load(', '.join([j.text for j in i.find('SSID').iter('encryption')]))    
        except Exception as e:
            load(None)
        row.append(i.attrib['last-time'])
        if debug: print(bcolors.FAIL + str(row) + bcolors.ENDC)
        csvwriter.writerow(row)
    file.close()

if __name__ == "__main__":
    XMLtoCSV("sniffing2.xml", 'sample6.csv')