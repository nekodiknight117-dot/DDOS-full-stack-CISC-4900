import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import Data_cleaner as dc
import ipaddress
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt




#method to call to change IP addresses to numbers 
def ip_to_int(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return int(ip_obj)
        elif ip_obj.version == 6:
            # IPv6 is too large for int64, so we truncate it to fit
            return int(ip_obj) % (2**63 - 1)
    except:
        return 0
    return 0
#method to call to change protocol name to ints
def prot_to_int(prot):
    asc = [ord(c) for c in prot]
    sum = 0
    for num in asc:
        sum += num
    return sum



# # dataframe createion using read.csv
# tempFile = pd.read_csv(r'C:\Local documents\test.csv')
# #calls the method ads a fuction parmeter and applys it to the ip address
# tempFile['192.168.1.10'] = tempFile['192.168.1.10'].apply(ip_to_int)
# #calls the method to change the ascii values from the protocol names as a fuctional parameter
# tempFile['TCP'] = tempFile['TCP'].apply(prot_to_int)
# tempFile['ARP'] = tempFile['ARP'].apply(prot_to_int)
# print(tempFile)
# #data is clean and will print the tensor with shape 8,n
# x = torch.tensor(tempFile.values,dtype=torch.float32)
# print(tempFile.dtypes)




file =  pd.read_csv(r'C:\Users\1dayk\Downloads\archive\DDoS_dataset.csv')
print(file.isnull().sum())
print(file.describe())
print(file.head())
print(file.columns)
file['Dest IP'] = file['Dest IP'].apply(ip_to_int).astype('int64')
file['Highest Layer'] = file['Highest Layer'].apply(prot_to_int)
file['Transport Layer'] = file['Transport Layer'].apply(prot_to_int)
print(file)
print(file.dtypes)



y = torch.tensor(file['target'].values,dtype=torch.float32)

file = file.drop(columns=['target', 'Dest IP', 'Source IP', 'Dest Port', 'Source Port'])
x= torch.tensor(file.values,dtype=torch.float32)



# print(x.shape)

# print(y.shape)


# create testing tensors

x_train,x_test,y_train,y_test = train_test_split(x,y,test_size=0.2,random_state=42)

scaler = StandardScaler()

x_train = scaler.fit_transform(x_train)
x_test = scaler.transform(x_test)

x_train_tensor = torch.tensor(x_train,dtype=torch.float32)
x_test_tensor = torch.tensor(x_test,dtype=torch.float32)

y_train_tensor = y_train.reshape(-1, 1)
y_test_tensor = y_test.reshape(-1, 1)

x_train_tensor=dc.csv_Tensor.noisemaker(x_train_tensor)


class DdosModel(nn.Module):
    def __init__(self,input_size):
        super(DdosModel,self).__init__()
        self.layer1= nn.Linear(input_size,16)
        self.dropout = nn.Dropout(0.5)
        self.layer2 = nn.Linear(16,8)
        self.output = nn.Linear(8,1)
        # turns previous layer into a value between 0 and 1
        self.sigmoid = nn.Sigmoid()
    def forward(self,x):
        x = torch.relu(self.layer1(x))
        x = self.dropout(x)
        x = torch.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.sigmoid(self.output(x))
        return x

model = DdosModel(x_train_tensor.shape[1])
       
criterion = nn.BCELoss()
# most effective training model for model training
optimizer = optim.Adam(model.parameters(),lr=0.01, weight_decay=1e-4)
losses = []
epochs = 800

for epoch in range(epochs):
    model.train()
    optimizer.zero_grad()
    outputs = model(x_train_tensor)
    loss = criterion(outputs,y_train_tensor)
    loss.backward()
    optimizer.step()
    losses.append(loss.item())
    if (epoch+1) % 200 == 0:
        model.eval()
        with torch.no_grad():
            test_outputs = model(x_test_tensor)
            test_loss = criterion(test_outputs, y_test_tensor)
        model.train()
        print(f'Epoch [{epoch+1}/{epochs}], Train Loss: {loss.item():.4f}, Test Loss: {test_loss.item():.4f}')
        
        
plt.plot(losses)
plt.show()


model.eval()

with torch.no_grad():
    outputs = model(x_test_tensor)
    predicted = outputs.round()

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

accuracy = accuracy_score(y_test, predicted)
precision = precision_score(y_test, predicted, zero_division=0)
recall = recall_score(y_test, predicted, zero_division=0)
f1 = f1_score(y_test, predicted, zero_division=0)
cm = confusion_matrix(y_test, predicted)

print(f'Accuracy: {accuracy:.4f}')
print(f'Precision: {precision:.4f}')
print(f'Recall: {recall:.4f}')
print(f'F1 Score: {f1:.4f}')
print(f'Confusion Matrix:\n{cm}')

# Save the trained model weights
torch.save(model.state_dict(), 'ddos_model.pth')
print("Model successfully saved to ddos_model.pth")


















#print(tempFile.columns)
# tempFile.iloc[:,0] = pd.factorize(tempFile.iloc[:,0])[0]
# tempFile.iloc[:,1] = pd.factorize(tempFile.iloc[:,1])[0]

# tempFile.iloc[:,3] = tempFile.iloc[:,3].str.replace('.','')
# for vals in tempFile.columns:
#     vals = tempFile[vals].astype('Float32').astype('category').cat.codes


# traffic_Data = pd.read_csv(r'C:\Users\1dayk\Downloads\archive\DDoS_dataset.csv')
# print(traffic_Data.head())
# x_input=dc.csv_Tensor(r'C:\Users\1dayk\Downloads\archive\DDoS_dataset.csv').clean(0,8)

# y_output= dc.csv_Tensor(r'C:\Users\1dayk\Downloads\archive\DDoS_dataset.csv').clean(8)

# print(x_input.item())

# Option 1: Absolute Path (Use r'' for Windows paths)
# traffic_Data = pd.read_csv(r'C:\Users\1dayk\traffic_logs.csv')

# Option 2: Relative Path (If file is in the same folder as this script)
# traffic_Data = pd.read_csv('traffic_logs.csv')
# Fix: Use 'columns' (not coloumns) and pass a single list of strings
# raw = traffic_Data.drop(columns=['target'])
# # Convert ALL columns to numbers (categorical codes) by treating them as strings first
# for col in raw.columns:
#     raw[col] = raw[col].astype(str).astype('category').cat.codes

# training_Input = torch.tensor(raw.values, dtype=torch.float32)
# print(training_Input.dtype)

# # Fix: Combine all column names into one list
# status = traffic_Data.drop(columns=[ 'Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port', 'Packet Length', 'Packets/Time'])

# for vals in status.columns:
#     status[vals] = status[vals].astype(str).astype('category').cat.codes

# training_output= torch.tensor(status.values, dtype=torch.float32)
# print(training_output.dtype)

# class simpleLogit(nn.Module):
#     def __init__(self, input_dim):
#         super().__init__()
#         self.linear = nn.Linear(input_dim,1)
#     def forward(self,x):
#         out= self.linear(x)
#         return torch.sigmoid(out)

# logitter = simpleLogit(training_Input.shape[1])

# logLoss = nn.BCELoss()

# logpredict = optim.SGD(logitter.parameters(),lr=0.01)
# print (f'  {type(logitter) } , {type(logLoss)}, {type(logpredict)}')
# for epoch in range(100):
#     status_pred = logitter(training_Input)
#     loss = logLoss(status_pred,training_output)
#     logpredict.zero_grad()
#     loss.backward()
#     logpredict.step()


# test_csv = pd.read_csv(r"C:\Local documents\test.csv")
# print(test_csv.head())
# print(f"Test Data Shape: {test_csv.shape}")

# for vals in test_csv.columns:
#     test_csv[vals] = test_csv[vals].astype(str).astype('category').cat.codes

# print(test_csv)
   

# logitest = torch.tensor(test_csv.values, dtype=torch.float32)
#     # Use .item() only if there is exactly 1 prediction, otherwise print 
#     # the tensor
# print(logitest[:5])
# predictions = logitter(logitest)

# print(predictions.tolist())

# # 2. View just the first 5 rows (cleaner for large data)
# print("First 5 predictions:\n", predictions[:5])
