import requests
import os.path
import json
from virustotal_python import Virustotal
# import rmv_js
# import rmv_hl

class VT:
    def __init__(self, key):
        self.key = key

    def upload_file(self, file):
        super(VT, self).__init__()

        vtotal = Virustotal(API_KEY=self.key)

        FILE_PATH = self.file = file

        files = {"file": (os.path.basename(FILE_PATH),
                          open(os.path.abspath(FILE_PATH), "rb"))}

        resp = vtotal.request("file/scan", files=files, method="POST")

        #print(resp.response_code)
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

def main():
    # api_key = input("Enter API key : ")
    api_key = "37bdd78a705ca736517be0e9e7196810414f1419f2a1c11278167a613dd4f83f"
    obj = VT(api_key)
    file_name = input("Enter your Malicious File Name : ")
    obj.upload_file(file_name)
    print("File Uploaded")
    sha256_id = obj.upload_file(file_name)['sha256']
    print("SHA_ID is : ", sha256_id)
    print("VirusTotal Report")
    obj.get_report(sha256_id)
    # choice = input(
    #     "Do you want to remove Executables like JavaScript and Hyperlinks from the Malicious File (y/n)? : ")
    # if choice == 'y':
    #     edited_file = rmv_js.remove_javascript(file_name)
    #     edited_file = rmv_hl.remove_hyperlinks(edited_file)
    #     obj.upload_file(edited_file)
    #     print("Uploaded Edited File")
    #     sha256_id_new = obj.upload_file(edited_file)['sha256']
    #     print('New SHA_ID is :', sha256_id_new)
    #     print("VirusTotal Report")
    #     obj.get_report(sha256_id_new)
    # elif choice == 'n':
    #     exit(1)

if __name__ == '__main__':
    main()
    
