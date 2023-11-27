import json

def read_json_file(file_path):
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)
            return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file {file_path}: {e}")
        return None

# Replace 'your_file.json' with the actual path to your JSON file
file_path = '/home/khattak01/Desktop/thesis/alert_ips-30.json'
json_data = read_json_file(file_path)

if json_data:
    print("JSON data:")
    print(len(json_data))
