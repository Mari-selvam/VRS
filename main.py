import pandas as pd
import numpy as np
file = "sample.log"

with open(file) as f: # read a logs
    logs = f.readlines()
    
    
# 10.0.0. 2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
IP_Address = dict({})
endpoints = dict({})
end_point_route = []
Suspicious = dict({})



for log in logs:
    
    # Task - 1 (Count Requests per IP Address)
    ip = log.split(" - - ")[0]
    
    if ip in IP_Address.keys():
        IP_Address[ip] += 1
    else:
        IP_Address[ip] = 1 
        
    
    # Task - 2 (Identify the Most Frequently Accessed Endpoint:)
    
    request_part = log.split('"')[1]
    endpoint = request_part.split(" ")[1]

    if endpoint in endpoints.keys():
        endpoints[endpoint] += 1
    else:
        endpoints[endpoint] = 1

        
        
    # Task -3 Detect Suspicious Activity
    
    request_part = log.split('"')[2]
    error_code = request_part.split(' ')[1]
    # print(type(error_code))
    
    if error_code == '401':
        if ip in Suspicious.keys():
            Suspicious[ip] += 1
        else:
            Suspicious[ip] = 1
    
    
    
    


# Task - 1
data = {
    "IP Address": list(IP_Address.keys()),
    "Request Count": list(IP_Address.values())
}
data = pd.DataFrame(data)

# Task - 3

Suspicious_data = {
    "IP Address":list(Suspicious.keys()),
    "Failed Login Attempts": list(Suspicious.values())
}

Suspicious_data = pd.DataFrame(Suspicious_data)




data.to_csv("log_analysis_results.csv")


print("Task - 1 (Count Requests per IP Address)")
print(data,end="\n \n \n ")
print("Task - 2 (Identify the Most Frequently Accessed Endpoint)",end='\n \n')

max_endpoint = np.argmax(list(endpoints.values())) # get a maximum end point Value 
max_endpoint = str(list(endpoints.keys())[max_endpoint]) # Value to find a endpoint

# print(f' max_endpoint => {max_endpoint}')


print(f"Most Frequently Accessed Endpoint:{'\n'} {max_endpoint} (Accessed {endpoints[max_endpoint]} times)")

endpoint = {"Frequently_Accessed_Endpoint":list(endpoints.keys()),
            "Count": list(endpoints.values())
            }

Frequent_Access = pd.DataFrame(endpoint)
Frequent_Access.to_csv("Frequently_Accessed_Endpoint.csv")


print("\n \n")
print("Task -3 Detect Suspicious Activity ")

print(Suspicious_data)
Suspicious_data.to_csv("log_Suspicious_results.csv") # export as csv

