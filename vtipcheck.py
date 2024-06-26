from csv import DictWriter
import sys
import csv
import argparse
import datetime
import json
import os
import requests
from progress.bar import IncrementalBar
from time import sleep
import ipaddress


# function to get result from virustotal for specified ip address


def get_ip_data(ip_addr, api_key):
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip_addr

    headers = {"accept": "application/json", "x-apikey": f"{api_key}"}
    try:
        response = requests.get(url, headers=headers)
        if response.json()["error"].get("message") == "Wrong API key":
            print("Wrong API Key provided. Check the API key and try again")
            exit()

        if response.json()["error"]["code"] == "QuotaExceededError":
            print("\nPublic API quota full")
            exit()

    except KeyError:
        return response.json()


# function to add required data in csv file


def data_entry(res_file, input_filename, api_key):
    csv_headers = [
        "IP",
        "Malicious Count",
        "Engines",
        "Country Code",
        "Last Analysis Date",
    ]

    with open(f"./{res_file}", "w") as result_file:
        header_write = csv.writer(result_file)
        header_write.writerow(csv_headers)
        result_file.close()
    with open(f"./{input_filename}", "r") as input_file:
        ip_address = input_file.readlines()
        incr_bar = IncrementalBar('Loading', max=len(
            ip_address), fill='|', suffix='%(percent)d%%')
        for ip in ip_address:
            ip = ip.rstrip("\n")
            try:
                check_ip = ipaddress.ip_address(ip)
                virustotal_data = get_ip_data(ip, api_key)

            except ValueError:
                print(f"Skipped {ip} as it is not valid ip address")
                continue

            mal_count = virustotal_data['data']["attributes"][
                "last_analysis_stats"
            ]["malicious"]
            country = virustotal_data["data"]["attributes"]["country"]
            epoch_time = virustotal_data['data']["attributes"][
                "last_analysis_date"
            ]
            last_analysis_date = datetime.datetime.fromtimestamp(
                epoch_time
            ).strftime("%Y-%m-%d")
            engine_list = []
            for engine_name_outer in virustotal_data["data"]["attributes"][
                "last_analysis_results"
            ]:
                engine_dict = virustotal_data['data']["attributes"][
                    "last_analysis_results"
                ][engine_name_outer]
                category = engine_dict.get("category")
                if category == "malicious":
                    engine_list.append(engine_dict.get("engine_name"))
            dict_data = {
                "IP": ip,
                "Malicious Count": mal_count,
                "Engines": engine_list,
                "Country Code": country,
                "Last Analysis Date": last_analysis_date,
            }

            with open(f"./{res_file}", "a") as out_file:
                dictwriter_object = DictWriter(
                    out_file, fieldnames=csv_headers)
                dictwriter_object.writerow(dict_data)
            incr_bar.next()
            print('\r')
            sleep(2)
        incr_bar.finish()
    print("File created successfully")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apikey",
        help="api key generated from VirusTotal",
        required=True,
    )
    parser.add_argument(
        "--file",
        help="txt file containing list of IP addresses to check. Ensure file is present in current directory",
        required=True,
    )
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])
    try:
        input_filename = args.file
        api_key = args.apikey
        res_file = "results_" + datetime.datetime.now().strftime("%Y-%m-%d") + ".csv"

        if os.path.exists(res_file):
            user_response = (
                input(
                    "results.csv file already exists. If you continue, this will overwrite to already existing file. Do you want to continue? (yes/no): "
                )
                .strip()
                .lower()
            )
            if user_response == "no":
                print("Exiting")
                exit()

        data_entry(res_file, input_filename, api_key)

    except KeyboardInterrupt:
        print("User interrupted")

    except FileNotFoundError:
        print("Filename is incorrect. Check the filename again and restart the program.")


if __name__ == "__main__":
    main()
