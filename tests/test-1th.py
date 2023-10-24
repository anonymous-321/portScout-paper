from pyspark import SparkConf, SparkContext

# Create a SparkConf and SparkContext
conf = SparkConf().setAppName("AddingDataToRDD")
sc = SparkContext(conf=conf)

# Create an initial RDD
initial_data = [
    {
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "src_port": 12345,
        "dst_port": 80,
    },
    {
        "src_ip": "192.168.1.3",
        "dst_ip": "192.168.1.4",
        "src_port": 54321,
        "dst_port": 8080,
    },
]

initial_rdd = sc.parallelize(initial_data)

# Create a list of dictionaries to add
new_dicts = [
    {
        "src_ip": "192.168.1.5",
        "dst_ip": "192.168.1.6",
        "src_port": 54322,
        "dst_port": 8081,
    },
    {
        "src_ip": "192.168.1.7",
        "dst_ip": "192.168.1.8",
        "src_port": 54323,
        "dst_port": 8082,
    },
    {
        "src_ip": "192.168.1.9",
        "dst_ip": "192.168.1.10",
        "src_port": 54324,
        "dst_port": 8083,
    },
]

# Define a function to append data to an RDD
def append_data(data):
    # This function takes an RDD element and appends the new data to it
    # Merge the data dictionary with each new_dict in the list of dictionaries
    return [dict(data, **new_dict) for new_dict in new_dicts]


# Use the flatMap transformation to append data to the initial RDD
combined_rdd = initial_rdd.flatMap(append_data)

# Perform calculations on the combined RDD
# For example, calculate the total number of records
total_records = combined_rdd.count()

# Collect and print the result
print("Total Records:", total_records)

# Stop the SparkContext
sc.stop()
