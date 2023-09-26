import datetime

def format_time(timestamp):
  # Convert the timestamp to a datetime object
  return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
  
  # Format the datetime object as a string
  # return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_time():
  return datetime.datetime.now().timestamp()