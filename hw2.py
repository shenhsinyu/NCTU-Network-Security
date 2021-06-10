import numpy as np
import os
import pandas as pd
import json
from pandas.io.json import json_normalize

path = "demo/309551033"
dirs = os.listdir(path)
for i in dirs:
    print("Attack_", i)
    file = open(path+'/'+i, 'r', encoding='utf-8')
    data = []
    for line in file.readlines():
        dic = json.loads(line)
        data.append(dic)

    df = pd.DataFrame.from_records(
        data, columns=["_index", "_type", "_id", "_score", "_source"])

    df_source = pd.json_normalize(df["_source"])
    FIELDS_TLS = ["tls.resumed"]
    FIELDS_IP = ["destination.ip"]
    FIELDS_PORT = ["destination.port"]

    try:
        df_hello = df_source[FIELDS_TLS]
        session = df_hello.describe()
        val = session['tls.resumed'][0]/len(df_source[FIELDS_TLS])
        if(val > 0.01):
            print("C&C")

        df_ip = df_source[FIELDS_IP]
        ip = df_ip.describe()
        val = ip['destination.ip'][1]/ip['destination.ip'][0]
        if(val > 0.03):
            print("IP_scan")

        else:
            df_port = df_source[FIELDS_PORT]
            df_port_scan = df_port.dropna(how='all')
            label, count = np.unique(df_port_scan, return_counts=True)
            if(len(label)/len(df_port) > 0.05):
                print("port_scan")
            else:
                sum_RDP = 0
                for i in range(len(df_port['destination.port'])):
                    if df_port['destination.port'][i] == 3389:
                        sum_RDP += 1

                if sum_RDP/len(df_port['destination.port']) > 0.8:
                    print("RDP bruteforce")

    # for ddos because it doesn't have tls.resumed
    except KeyError:
        df_port = df_source[FIELDS_PORT]
        sum_ddos = 0
        for i in range(len(df_port['destination.port'])):
            if df_port['destination.port'][i] == 22:
                sum_ddos += 1
        if sum_ddos/len(df_port['destination.port']) > 0.9:
            print("DDoS")
