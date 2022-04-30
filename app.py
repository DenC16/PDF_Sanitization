import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd
import base64

import requests
import os.path
import json
from virustotal_python import Virustotal
import rmv_js
import rmv_hl

class VT:
    def __init__(self, key):
        self.key = key

    def upload_file(self, file):
        super(VT, self).__init__()
        vtotal = Virustotal(API_KEY=self.key)
        self.file = file
        FILE_PATH = file

        files = {"file": (os.path.basename(FILE_PATH), open(FILE_PATH, "rb"))}
        resp = vtotal.request("file/scan", files=files, method="POST")

        data = resp.json()
        return data


    def get_report(self, sha):
        super(VT, self).__init__()
        self.sha = sha
        url = "https://www.virustotal.com/api/v3/files/" + sha

        #print(url)
        headers = {
            "Accept": "application/json",
            "x-apikey": self.key
        }

        response = requests.request("GET", url, headers=headers)
        data = response.text
        json_data = json.loads(data)

        vendors = json_data["data"]["attributes"]["last_analysis_results"]

        cnt = 0
        mal_vendor_list = []
        undet_vendor_list = []

        for key, values in vendors.items():
            #print(key, values['category'])
            if values['category'] == 'malicious':
                cnt += 1
                mal_vendor_list.append(key)
            elif values['category'] == 'undetected':
                undet_vendor_list.append(key)

        return cnt

############################################################
# Page title
st.markdown("""
# PDF Sanitizer for Malware Analysis
This app allows you to analyze your file & to check if it is Malicious or not and presents a report .

**Credits**
- App built in `Python` + `Streamlit` by [Dhyaneswaran](https://bit.ly/34Fjfue) 
---
""")
st.write("Enter your virus Total API Key  : ")
api_key = st.text_input("Key : ")
# api_key = "37bdd78a705ca736517be0e9e7196810414f1419f2a1c11278167a613dd4f83f"

st.header('Enter your Malicious File')
uploaded_file = st.text_input("Upload your input file")

st.write("The current file is ",uploaded_file)

if uploaded_file is None:
    st.markdown("""
    [Example input file](https://github.com/DenC16/PDF_Sanitizer/blob/main/vfile_1)
    """)

def create_download_link(val, filename):
    b64 = base64.b64encode(val)  # val looks like b'...'
    return f'<a href="data:application/octet-stream;base64,{b64.decode()}" download="{filename}.pdf">Download file</a>'


if st.button('Analyse'):
    obj = VT(api_key)
    file_name = uploaded_file
    obj.upload_file(file_name)

    sha256_id = obj.upload_file(file_name)['sha256']
    init_count = obj.get_report(sha256_id)

    st.write("Initial Count is : ",init_count)

    edited_file = rmv_js.remove_javascript(file_name)
    edited_file = rmv_hl.remove_hyperlinks(edited_file)
    obj.upload_file(edited_file)
    sha256_id_new = obj.upload_file(edited_file)['sha256']
    changed_count = obj.get_report(sha256_id_new)

    # st.write("After Cleaning : ",changed_count)

    frame1 = {'Virus File Name': [file_name], 'Virus_SHA_ID': [sha256_id],
            'No. of Vendors flagged': [init_count]
            }
    frame2 = {'Changed Virus File Name': [edited_file], 'Virus_new_SHA_ID': [sha256_id_new],
        'No. of Vendors flagged again': [changed_count]}

    df1 = pd.DataFrame(frame1)
    df2 = pd.DataFrame(frame2)

    df1.to_csv('DataFrame_initial.csv', index=False)
    df2.to_csv('DataFrame_final.csv', index=False)

    load_data1 = pd.read_csv('DataFrame_initial.csv', index_col=False)
    load_data2 = pd.read_csv('DataFrame_final.csv', index_col=False)
    

    st.header('**Initial Report on scanning**')
    st.write(load_data1)

    st.header('**Final Report after Editing & Scanning**')
    st.write(load_data2)

    count = load_data1._get_value(0, 'No. of Vendors flagged')
    changed_count = load_data2._get_value(0, 'No. of Vendors flagged again')

    st.set_option('deprecation.showPyplotGlobalUse', False)

    fig = plt.figure()
    ax = fig.add_axes([0, 0, 1, 1])
    numb = ['Initial Count', 'Final Count']
    no_cnt = [count, changed_count]
    ax.bar(numb, no_cnt)
    st.pyplot()

    new_edited_file_vt = edited_file

    with open(new_edited_file_vt, "rb") as pdf_file:
        new_pdf = pdf_file.read()

    st.sidebar.download_button(label="Download New PDF",
                               data=new_pdf,
                               file_name=new_edited_file_vt + ".pdf",
                               mime='application/octet-stream')


else:
    st.info('Upload input file name to start!')
