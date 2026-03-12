import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# Example dataset
data = {
    "duration":[1,2,3,10,12,15,2,3],
    "src_bytes":[100,200,150,6000,7000,8000,120,180],
    "dst_bytes":[200,250,300,50,40,60,220,240],
    "protocol":[0,0,1,1,1,1,0,0],
    "attack":[0,0,0,1,1,1,0,0]
}

df = pd.DataFrame(data)

X = df[["duration","src_bytes","dst_bytes","protocol"]]
y = df["attack"]

model = RandomForestClassifier()
model.fit(X,y)

# save model
pickle.dump(model, open("model.pkl","wb"))

print("Model trained successfully")