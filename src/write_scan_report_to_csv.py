#!/usr/bin/python

import json
import csv
import os
import argparse
import pandas as pd
import ast
import json

def get_uniques(df,feature):
    uniques = []
    try:
        for i in df[feature]:
            for j in ast.literal_eval(i):
                if(j not in uniques):
                    uniques.append(j)
    except Exception as e:
        print("[!] Exception: {} with value {}".format(e,i))
        exit()
    return uniques

OUTPUT_FOLDER = 'scan_report_csv'
DEBUG = False
DEBUG_MORE = False
read = 0
written = 0

parser = argparse.ArgumentParser(description='Parse scan behaviour report and write to csv file.')
parser.add_argument("-i", "--input", required=True, help="Input folder containing the reports.")
parser.add_argument("-o", "--output", required=True, help="Output file name. The file is created within \'scan_report_csv\' folder.")
parser.add_argument('--noheader', dest='header', action='store_false',help="Do not include header row.")
parser.set_defaults(header=True)

args = parser.parse_args()

if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

outfile = os.path.join(OUTPUT_FOLDER,args.output)
rawfile = os.path.join(OUTPUT_FOLDER,args.output+'.raw')
if os.path.exists(outfile) or os.path.exists(rawfile):
    print("[!] Output file exists. Abort.")
    exit()

print "[*] Reading features from reports"
for filename in os.listdir(args.input):

    inpath = os.path.join(args.input,filename)
    with open(inpath) as file:
        package_name = None
        data_folder = None
        try:
            obj = json.load(file)
            read += 1
        except Exception as e:
            print("[!] Exception loading file: {}. Skipping".format(e))
            continue

        try:
            positives = obj['positives']
        except:
            print("[!] positives not found:{} Skipping.".format(filename))
            continue
        try:
            additional_info = obj['additional_info']
        except:
            print("[!] additional_info not found:{} Skipping.".format(filename))
            continue
        try:
            file_types = additional_info['compressedview']['file_types']
        except:
            if DEBUG:
                print("[!] file_types not found: {}".format(filename))
            file_types = {}
        try:
            contacted_domains = additional_info['contacted_domains']
        except:
            if DEBUG:
                print("[!] contacted_domains not found:{}".format(filename))
            contacted_domains = []
        if contacted_domains == []: contacted_domains = ['None'] 
        
        # Androguard
        try:
            androguard = additional_info['androguard']
        except:
            print("[!] androguard not found. Skipping:{}".format(filename))
            continue
        
        try:
            package_name = androguard['Package']
            data_folder = "/data/data/" + package_name
        except:
            print("[!] Package name not found: {}. Skipping.".format(filename))
            continue
        
        try:
            intent_filters = androguard['intent-filters']
            try:
                if_services = []
                for service in intent_filters['Services']:
                    for action in intent_filters['Services'][str(service)]['action']:
                        if package_name not in action:
                            if_services.append(str(action))
            except:
                if DEBUG:
                    print("[!] services not found:{}".format(filename))
                if_services = []
            
            try:
                if_activities = []
                for activity in intent_filters['Activities']:
                    for action in intent_filters['Activities'][str(activity)]['action']:
                        if package_name not in action:
                            if_activities.append(str(action))
            except:
                if DEBUG:
                    print("[!] activities not found:{}".format(filename))
                if_activities = []
            
            try:
                if_receivers = []
                for receiver in intent_filters['Receivers']:
                    for action in intent_filters['Receivers'][str(receiver)]['action']:
                        if package_name not in action:
                            if_receivers.append(str(action))
            except:
                if DEBUG:
                    print("[!] receivers not found: {}".format(filename))
                if_receivers = []
           
        except:
            if DEBUG:
                print("[!] intent_filters not found:{}".format(filename))
            services = []
            activities = []
            receivers = []
        
        if if_services == []: if_services = ['None']
        if if_activities == []: if_activities = ['None']
        if if_receivers == []: if_receivers = ['None']
        
        try:
            cert_cn = [androguard['certificate']['Subject']['CN']]
        except:
            if DEBUG:
                print("[!] Certificate subject CN not found:{}".format(filename))
            cert_cn = []
        if cert_cn == []: cert_cn = ['None']

        try:
            libraries = androguard['Libraries']
        except:
            if DEBUG:
                print("[!] Libraries not found:{}".format(filename))
            libraries = []
        if libraries == []: libraries = ['None']

        try:
            perm_normal = androguard['RiskIndicator']['PERM']['NORMAL']
        except Exception as e:
            perm_normal = 0
        try:
            perm_money = androguard['RiskIndicator']['PERM']['MONEY']
        except Exception as e:
            perm_money = 0
        try:
            perm_privacy = androguard['RiskIndicator']['PERM']['PRIVACY']
        except Exception as e:
            perm_privacy = 0
        try:
            perm_sms = androguard['RiskIndicator']['PERM']['SMS']
        except Exception as e:
            perm_sms = 0
        try:
            perm_internet = androguard['RiskIndicator']['PERM']['INTERNET']
        except Exception as e:
            perm_internet = 0
        try:
            perm_signatureorsystemordevelopment = androguard['RiskIndicator']['PERM']['SIGNATUREORSYSTEMORDEVELOPMENT']
        except Exception as e:
            perm_signatureorsystemordevelopment = 0
        try:
            perm_dangerous = androguard['RiskIndicator']['PERM']['DANGEROUS']
        except Exception as e:
            perm_dangerous = 0
        try:
            perm_call = androguard['RiskIndicator']['PERM']['CALL']
        except Exception as e:
            perm_call = 0
        try:
            perm_gps = androguard['RiskIndicator']['PERM']['GPS']
        except Exception as e:
            perm_gps = 0
        try:
            perm_signatureorsystem = androguard['RiskIndicator']['PERM']['SIGNATUREORSYSTEM']
        except Exception as e:
            perm_signatureorsystem = 0
        try:
            perm_signature = androguard['RiskIndicator']['PERM']['SIGNATURE']
        except Exception as e:
            perm_signature = 0
        try:
            permissions = []
            for permission in androguard['Permissions']:
                if package_name not in permission:
                    permissions.append(str(permission))
        except:
            if DEBUG:
                print("[!] permissions not found: {}".format(filename))
            permissions = []
        if permissions == []: permissions = ['None']
        
        # android-behaviour
        try:
            android_behaviour = additional_info['android-behaviour']
            try:
                accessed_files = []
                for accessed_file in android_behaviour['accessed_files']:
                    if data_folder not in accessed_file and package_name not in accessed_file and '.tcookieid' not in accessed_file:
                        accessed_files.append(str(accessed_file))
            except:
                if DEBUG:
                    print("[!] accessed_files not found: {}".format(filename))
                accessed_files = []
            try:
                opened_files = []
                for opened_file in android_behaviour['opened_files']:
                    if data_folder not in opened_file and "APP_ASSETS" not in opened_file and package_name not in opened_file:
                        opened_files.append(str(opened_file))
            except:
                if DEBUG:
                    print("[!] opened_files not found: {}".format(filename))
                opened_files = []
            try:
                dynamically_called_methods = []
                for dynamically_called_method in android_behaviour['dynamically_called_methods']:
                    dynamically_called_methods.append(str(dynamically_called_method['method']))
            except:
                if DEBUG:
                    print("[!] dynamically_called_methods not found: {}".format(filename))
                dynamically_called_methods = []
            try:
                started_receivers = []
                for started_receiver in android_behaviour['started_receivers']:
                    if package_name not in started_receiver:
                        started_receivers.append(str(started_receiver))
            except:
                if DEBUG:
                    print("[!] started_receivers not found: {}".format(filename))
                started_receivers = []
            try:
                external_programs = []
                for external_program in android_behaviour['external_programs']:
                    external_programs.append(str(external_program))
            except:
                if DEBUG:
                    print("[!] external_programs not found: {}".format(filename))
                external_programs = []
        except:
            if DEBUG:
                print("[!] android_behaviour not found: {}".format(filename))
            accessed_files = []
            opened_files = []
            dynamically_called_methods = []
            started_receivers = []
            external_programs = []

        if accessed_files == []: accessed_files = ['None']
        if opened_files == []: opened_files = ['None']
        if dynamically_called_methods == []: dynamically_called_methods = ['None']
        if started_receivers == []: started_receivers = ['None']
        if external_programs == []: external_programs = ['None']
        
        try:
            f_prot_unpacker = [additional_info['f-prot-unpacker']]
            #if "appended" in f_prot_unpacker or "UTF-8" in f_prot_unpacker:
            #    f_prot_unpacker = "None"
        except:
            if DEBUG:
                print("[!] f-prot-unpacker not found: {}".format(filename))
            f_prot_unpacker = []
        if f_prot_unpacker == []: f_prot_unpacker = ['None']

        with open(rawfile, "a") as f:
            w = csv.writer(f)
            if written is 0:
                w.writerow(["file_hash","package_name","positives", "file_types", "contacted_domains", "if_services", "if_activities", "if_receivers","perm_normal","perm_money","perm_privacy","perm_sms","perm_internet","perm_signatureorsystemordevelopment","perm_dangerous","perm_call","perm_gps","perm_signatureorsystem","perm_signature","permissions","accessed_files","opened_files","dynamically_called_methods","started_receivers","external_programs","cert_cn","f_prot_unpacker"])
            w.writerow([filename,package_name,positives,file_types,contacted_domains,if_services,if_activities,if_receivers,perm_normal,perm_money,perm_privacy,perm_sms,perm_internet,perm_signatureorsystemordevelopment,perm_dangerous,perm_call,perm_gps,perm_signatureorsystem,perm_signature,permissions,accessed_files,opened_files,dynamically_called_methods,started_receivers,external_programs,cert_cn,f_prot_unpacker])            
            written += 1

# TODO: pre-processing needed for 'contacted_domains' to reduce unique feature names
df = pd.read_csv(rawfile,index_col=0)
for feature_list_name in ['permissions','file_types','if_services','if_activities','if_receivers','accessed_files','opened_files','dynamically_called_methods','started_receivers','external_programs','cert_cn','f_prot_unpacker']:
# Test without 'accessed_files' and 'opened_files'
#for feature_list_name in ['permissions','file_types','if_services','if_activities','if_receivers','dynamically_called_methods','started_receivers','external_programs','cert_cn','f_prot_unpacker']:
    print("[*] Converting {} to features".format(feature_list_name))
    # Get unique features from raw feature
    uniques_list = get_uniques(df,feature_list_name)
    
    # Replace empty strings with 'None'
    for (i, item) in enumerate(uniques_list):
        if item == '' or item == None:
            uniques_list[i] = 'None'

    # Add prefix and take care of difficult characters
    try:
        uniques_list_with_prefix = [feature_list_name + "-" + x.encode('ascii','ignore').replace(',',';').replace('\n', ' ').replace('\r', '') for x in uniques_list]
    except Exception as e:
        print("[!] Exception adding prefix: {}".format(e))
        exit()
    print("[*] {} unique values found".format(len(uniques_list_with_prefix)))

    # Create dict and initialize with zeros
    uniques_dict = {x:0 for x in uniques_list_with_prefix}

    # Add new columns
    df = df.assign(**uniques_dict)

    # iterate df rows and update values to new columns
    try:
        for index, row in df.iterrows():
            raw_feature = ast.literal_eval(row[feature_list_name])
            # must replace empty strings as above with unique_list
            if raw_feature == [None] or raw_feature == [''] or raw_feature == []:
                raw_feature = ['None']
                
            if(type(raw_feature) is dict):
                for item,value in raw_feature.iteritems():
                    # Must add prefix and take care of difficult characters as done previously
                    df.at[index,feature_list_name + "-" + item.encode('ascii','ignore').replace(',',';').replace('\n', '').replace('\r', '')] = value
            elif(type(raw_feature) is list):
                for item in raw_feature:
                    # Must add prefix and take care of unicode and ',' characters as done previously
                    df.at[index,feature_list_name + "-" + item.encode('ascii','ignore').replace(',',';').replace('\n', '').replace('\r', '')] = 1
            else:
                print("[!] Unknown type of raw feature:{}".format(type(raw_feature)))
                exit()
    except Exception as e:
        print "[!] Error while processing {}: {}".format(feature_list_name,e)
        exit()

    if DEBUG_MORE:
        pd.set_option('display.max_columns', None)
        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_colwidth', -1)
        df2 = df.filter(regex=feature_list_name)
        print(df2.loc['001e0f67b5bb9ddab14facbef94791eaed0eb939bcb651d19dafd0e2a05d8178'])

# Drop unnecessary features
drop_list = ['package_name','permissions','file_types','contacted_domains','if_services','if_activities','if_receivers','accessed_files','opened_files','dynamically_called_methods','started_receivers','external_programs','cert_cn','f_prot_unpacker']

df.drop(columns=drop_list,inplace=True)

print("[*] Total number of features: {}".format(len(df.columns)))
# write df to csv
with open(outfile, "w") as f:
    df.to_csv(f,encoding='utf8')

print("[*] Done")
