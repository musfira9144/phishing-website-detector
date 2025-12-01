# 🛡️ Phishing Website Detector  

A Machine Learning–powered web app that detects **phishing websites** based on URL and webpage features.  
Built with **Python, scikit-learn, and Streamlit**, this project demonstrates the complete ML pipeline — from dataset preprocessing to deployment with a user-friendly interface.  


---

## 📊 Dataset  
We used the **Phishing Dataset for Machine Learning** from Kaggle:  
🔗 [Kaggle Dataset](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning)  

- 10,000 websites (balanced: 50% phishing, 50% legitimate)  
- 48 engineered lexical and content-based features  

---

## 🧠 Model  
- **Algorithm used:** Extra Trees Classifier (best performance among LR, RF, GB, SVM, etc.)  
- Accuracy: ~85% on test set  
- Features: URL structure, suspicious words, HTTPS usage, subdomain levels, etc.  

---

## 💻 Tech Stack  
- **Frontend:** Streamlit (dark theme UI, interactive gauges & feature explanations)  
- **Backend/ML:** scikit-learn, joblib, pandas, numpy  
- **Visualization:** Plotly  
- **Deployment:** Streamlit Community Cloud  

---
## 🔗 Streamlit Link
👉 **[Click to Open Streamlit App](https://phishing-website-detector-gjp5icnx45ye6jef3ch675.streamlit.app/)** 


