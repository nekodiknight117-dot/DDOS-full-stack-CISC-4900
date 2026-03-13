 Swell Scan – Web-based AI-powered network forensics


Overview


Swell Scan is a tool for cybersecurity professionals, hobbyists, and students looking for no-code network log analysis.
Powered by machine learning, this tool analyzes network traffic across various protocols to identify DDoS attacks. While most contemporary IT tools rely on complex CLIs or local GUI installations, Swell Scan is entirely web-based—eliminating barriers for those working in resource-limited environments. The no-code design allows for the transparent identification of network anomalies.


Key Functionalities


1. Log Parsing
    1.1 Automated Analysis: Swell Scan parses network logs in CSV (Comma Separated Values) format to identify DDoS behavior.

    1.2 Intelligent Detection: The model evaluates nine different features to identify anomalous behaviors. This is powered        by  a Logistic Regression model trained in PyTorch.

2. No-Code Design


   2.1 Seamless Data Processing: The web interface allows users to directly import files into the models, utilizing a             user- friendly design to enhance usability.


   2.2 Historical Insights: Users can easily review previous log sessions using the integrated Analysis Dashboard.


   2.3 Optimized UI: The transparent user interface highlights crucial data points without overwhelming the user.


3. AI power Analysis and specifications
    3.1 Through logistic regression the Swell Scan machine learning model can make binary classifications on log data to            identify anomolies.

   3.2 Data analysis:The model is trained on tabular csv data from almost 400,000 connection accross many applications from        instagram to niche blogs.

   3.2.1 training data set: the data was trained off using the following format:

       Highest Layer- in refrence to the osi model layers for connections


       Transport Layer - transport protocol being used


       Source IP - origination address


       Dest IP -  destination address

       Source Port what port service the connection is using


       Dest Port - what port service the connection will arrive to


       Packet Length -  the size of the packet in bytes


       Packets/Time -  the duration of the connection
   3.3 Logisitic regression classification- This shallow learning model classifies network log records based on thier
   attributes relative association with known malicous connections.In depth expplanations and supplemental material can be found [here](https://en.wikipedia.org/wiki/Logistic_regression).


🛠️ Tech Stack
Frontend

   	Styling: Tailwind CSS v4.2.1
  
   	Languages: HTML5, CSS3, JavaScript (ES2025)

Backend
  	Framework: FastAPI

  	Database Toolkit: SQLAlchemy 2.0.48

  	Language: Python 3.14.x

AI & Data Science
 	Deep Learning: PyTorch (Logistic Regression Model)

  	Data Manipulation: Pandas

  	Machine Learning: Scikit-learn

  	Visualization: Matplotlib

  	Data Source: Kaggle (DDoS Network Traffic Dataset)

Infrastructure & Hosting
  	Cloud Provider: Amazon Web Services (AWS)

  	Compute: Amazon EC2 (t2.micro/t3.small instance)

  	Deployment: Hosted via FastAPI on a Linux-based EC2 environment.

   
  
   
