import pandas as pd
import torch 
import torch.nn as nn
import torch.optim as optim
class csv_Tensor:
    def __init__(self,file):
        self.file=pd.read_csv(file)
    
    def noisemaker(training):
        noise_factor = 0.1
        noise = torch.randn_like(training) * noise_factor
        noisy_data = training+noise
        return noisy_data
        
        
    
    
    def clean(self,column_index):
        tempFile =self.file.iloc[:,column_index]
        for vals in tempFile.columns:
            vals = tempFile[vals].astype('float32').astype('category').cat.codes
        
        return torch.tensor(tempFile.values,dtype=torch.float32)
    
    def clean(self,startIndex,stopIndex):
        tempFile = self.file.iloc[startIndex:stopIndex]
        tempFile = pd.get_dummies(tempFile,columns=['Highest Layer','Transport Layer'])
        
        for vals in tempFile.columns:
             vals = tempFile[vals].astype('Float32').astype('category').cat.codes
        print(tempFile.head())

        return torch.tensor(tempFile.values,dtype=torch.float32)
    def dataframe_to_tensor(self,dataframe):
        for vals in dataframe.columns:
            dataframe[vals] = dataframe[vals].astype('Float32').astype('category').cat.codes
        return torch.tensor(dataframe.values,dtype=torch.float32)
    
    def dataframe_to_tensor(dataframe):
        for vals in dataframe.columns:
            dataframe[vals] = dataframe[vals].astype('Float32').astype('category').cat.codes
        return torch.tensor(dataframe.values,dtype=torch.float32)

        