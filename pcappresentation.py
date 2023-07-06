from scapy.all import *
import pandas as pd
import argparse

#Making the pcap capture ready to be accessed
def read_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    return packets

#Displaying the relevant data from the capture(Can extract and display further information)
def process_packets(packets):
    data = []
    for packet in packets:
        #Accessing IP Layer information
        ip_layer = packet.getlayer(IP)
        # Accessing TCP Layer information
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        row = {
            "Source IP": ip_layer.src,
            "Destination IP": ip_layer.dst,
            "Protocol": ip_layer.proto, 
            "Source Port": transport_layer.sport if transport_layer else None,
            "Destination Port": transport_layer.dport if transport_layer else None
            # Possible to add more fields
        }
        data.append(row)
    #Converting the newly computed list to a dataframe
    df = pd.DataFrame(data)
    return df

#The option to analyze based on specific IP
def display_data(df, ip_filter):
    if ip_filter:
        filtered_df = df[(df["Source IP"] == ip_filter) | (df["Destination IP"] == ip_filter)]
        if filtered_df.empty:
            print("No matching IP address found in the capture.")
        else:
            print(filtered_df)
    else:
        print(df)

# Making sure there's a pcap file given as arg
#def get_pcap_file():
#    pcap_file = input("Enter the path to the PCAP file: ")
#    return pcap_file

    

def run(pcap_file, ip_filter):
    packets = read_pcap(pcap_file)
    df = process_packets(packets)
    display_data(df, ip_filter)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-ip", "--ip_filter", help="IP address to filter the results")
    args = parser.parse_args()

    run(args.pcap_file, args.ip_filter)
    