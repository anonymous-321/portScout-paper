import json

def read_json_file(json_path):
    with open(json_path, 'r') as file:
        return json.load(file)

def check_files_and_ips(file_1_path, file_2_path):
    file_1 = read_json_file(file_1_path)
    file_2 = read_json_file(file_2_path)

    results = {}
    found = 0
    not_found = 0
    for file_path, ips_file_1 in file_1.items():
        file_count = 0
        for d in file_2:
            if file_path ==d["file"]:
                # ips_set_file_1 = set(ips_file_1)
                # print(ips_file_1)
                file_count = file_count + 1
        
        percentage = (file_count/len(ips_file_1) ) * 100
        # print(percentage)
        if percentage > 25:
            results[file_path] = {
                "file_exists_in_file_2": True,
                "total_ips": len(list(set(ips_file_1))),
                "found_ips": file_count,
                "percentage": (file_count/len(ips_file_1) ) * 100,
            }
            found+=1
        else:
            results[file_path] = {
                    "file_exists_in_file_2": False,
                    "total_ips": len(list(set(ips_file_1))),
                    "found_ips": file_count,
                    "percentage": (file_count/len(ips_file_1) ) * 100,
            }
            not_found+=1
    results["scan_detected"] = found
    results["scan_not_detected"] = not_found
    
    print("found >>",found)
    print("not_found >>",not_found)
    return results


# File paths
file_1_path = '/home/khattak01/Desktop/thesis/results/ips_used_for_scanning.json'
file_2_path = '/home/khattak01/Desktop/thesis/results/[our]-results/alert_ips-40.json'

import os
# Check files and IPs
results = check_files_and_ips(file_1_path, file_2_path)
# print(results)
# # Save results to JSON
output_json_path = '[ours]-attack_results-20.json'

# # Check if the file exists and remove it
# if os.path.exists(output_json_path):
#     os.remove(output_json_path)
#     print(f"Existing file {output_json_path} removed.")

# Rest of your code
with open(output_json_path, 'w') as output_file:
    json.dump(results, output_file, indent=2)

print(f"Results saved to {output_json_path}")

