import numpy as np
import joblib
import streamlit as st

# Load the saved model
model = joblib.load('StackingEnsemble.joblib')

def intrusion(input_data):
    input_data_as_numpy_array = np.asarray(input_data)
    input_data_reshaped = input_data_as_numpy_array.reshape(1, -1)
    prediction = model.predict(input_data_reshaped)
    return prediction

def main():
    st.title('Intrusion Detection using ML')

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        RST_Flag_Count = st.number_input("RST Flag Count", min_value=0, format="%d")
    with col2:
        Fwd_Packet_Length_Max = st.number_input("Fwd Packet Length Max", min_value=0, format="%d")
    with col3:
        Packet_Length_Std = st.number_input("Packet Length Std", min_value=0.0, format="%.2f")
    with col4:
        Total_Length_of_Fwd_Packet = st.number_input("Total Length of Fwd Packet", min_value=0, format="%d")
    with col1:
        Packet_Length_Variance = st.number_input("Packet Length Variance", min_value=0.0, format="%.2f")
    with col2:
        Flow_Bytes = st.number_input("Flow Bytes/s", min_value=0.0, format="%.2f")
    with col3:
        Fwd_Packet_Length_Mean = st.number_input("Fwd Packet Length Mean", min_value=0.0, format="%.2f")
    with col4:
        FIN_Flag_Count = st.number_input("FIN Flag Count", min_value=0, format="%d")
    with col1:
        Packet_Length_Max = st.number_input("Packet Length Max", min_value=0, format="%d")
    with col2:
        Fwd_RST_Flags = st.number_input("Fwd RST Flags", min_value=0, format="%d")
    with col3:
        Fwd_Segment_Size_Avg = st.number_input("Fwd Segment Size Avg", min_value=0.0, format="%.2f")
    with col4:
        Packet_Length_Mean = st.number_input("Packet Length Mean", min_value=0.0, format="%.2f")
    with col1:
        Bwd_Packet_Length_Std = st.number_input("Bwd Packet Length Std", min_value=0.0, format="%.2f")
    with col2:
        Average_Packet_Size = st.number_input("Average Packet Size", min_value=0.0, format="%.2f")
    with col3:
        Bwd_Segment_Size_Avg = st.number_input("Bwd Segment Size Avg", min_value=0.0, format="%.2f")
    with col4:
        Bwd_RST_Flags = st.number_input("Bwd RST Flags", min_value=0, format="%d")
    with col1:
        Bwd_Packet_Length_Max = st.number_input("Bwd Packet Length Max", min_value=0, format="%d")
    with col2:
        Flow_IAT_Mean = st.number_input("Flow IAT Mean", min_value=0.0, format="%.2f")
    with col3:
        Bwd_Packet_Length_Mean = st.number_input("Bwd Packet Length Mean", min_value=0.0, format="%.2f")
    with col4:
        Subflow_Bwd_Bytes = st.number_input("Subflow Bwd Bytes", min_value=0, format="%d")

    if st.button('PREDICT'):
        input_features = [
            RST_Flag_Count, Fwd_Packet_Length_Max, Packet_Length_Std,
            Total_Length_of_Fwd_Packet, Packet_Length_Variance, Flow_Bytes,
            Fwd_Packet_Length_Mean, FIN_Flag_Count, Packet_Length_Max,
            Fwd_RST_Flags, Fwd_Segment_Size_Avg, Packet_Length_Mean,
            Bwd_Packet_Length_Std, Average_Packet_Size, Bwd_Segment_Size_Avg,
            Bwd_RST_Flags, Bwd_Packet_Length_Max, Flow_IAT_Mean,
            Bwd_Packet_Length_Mean, Subflow_Bwd_Bytes
        ]

        result = intrusion(input_features)

        if result[0] == 0:
            st.success('✅ No Attack Detected!')
        elif result[0] == 1:
            st.error('🚨 Attack Detected: DDoS')
        elif result[0] == 2:
            st.warning('⚠️ Attack Detected: Portscan')
        elif result[0] == 3:
            st.warning('⚠️ Attack Detected: Web Attack')

if __name__ == '__main__':
    main()
