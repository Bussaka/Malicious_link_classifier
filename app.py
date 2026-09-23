import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt

# UI Configuration
st.set_page_config(page_title="ThreatScanner", page_icon="🛡️", layout="centered")
st.title("🛡️ Real-Time URL Threat Scanner")
st.write("Paste a link below to analyze its structural features and detect evasion tactics.")

# User Input
url_input = st.text_input("Target URL:", placeholder="https://example.com/login")

# Action Button
if st.button("Scan URL"):
    if not url_input:
        st.warning("Please enter a URL to scan.")
    else:
        with st.spinner("Analyzing lexical features..."):
            try:
                # Send the URL to our running FastAPI backend
                response = requests.post(
                    "http://127.0.0.1:8000/scan", 
                    json={"url": url_input}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data["status"]
                    confidence = data["confidence"]
                    
                    # Render the results visually
                    if status == "Malicious":
                        st.error(f"🚨 **Threat Detected!** This URL is classified as {status}.")
                    else:
                        st.success(f"✅ **Safe.** This URL is classified as {status}.")
                        
                    st.write(f"**Model Confidence:** {confidence}%")
                    st.progress(int(confidence))
                    
                    # Fetch and render the SHAP Explainability Chart
                    explanation = data.get("explanation", {})
                    if explanation:
                        st.markdown("---")
                        st.subheader("🧠 Model Decision Breakdown")
                        st.write("This chart shows exactly which features pushed the model toward predicting 'Malicious' (Red) or 'Safe' (Blue).")
                        
                        # Convert the dictionary to a DataFrame for plotting
                        shap_df = pd.DataFrame(list(explanation.items()), columns=['Feature', 'Impact'])
                        
                        # Sort by absolute impact so the most important features appear at the top
                        shap_df['Abs_Impact'] = shap_df['Impact'].abs()
                        shap_df = shap_df.sort_values(by='Abs_Impact', ascending=True)
                        
                        # Assign colors: Positive = Red (Malicious), Negative = Blue (Safe)
                        colors = ['#FF4B4B' if val > 0 else '#1F77B4' for val in shap_df['Impact']]
                        
                        # Render the Matplotlib chart
                        fig, ax = plt.subplots(figsize=(8, 5))
                        ax.barh(shap_df['Feature'], shap_df['Impact'], color=colors)
                        ax.set_xlabel("Impact on Malicious Probability")
                        ax.set_title("SHAP Feature Contributions")
                        ax.grid(axis='x', linestyle='--', alpha=0.5)
                        
                        st.pyplot(fig)

                else:
                    st.error("Error: The API rejected the request. Check the backend server.")
                    
            except requests.exceptions.ConnectionError:
                st.error("Connection Failed: Ensure your FastAPI server is running on port 8000.")