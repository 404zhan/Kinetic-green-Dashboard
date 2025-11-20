import os, traceback, streamlit as st
os.environ["RICH_TRACEBACK"] = "true"

def _debug_startup():
    try:
        pass
    except Exception as e:
        st.error("Startup Error:")
        st.code(traceback.format_exc())
        raise
_debug_startup()

try:
    import can
    from can import BLFReader
    CAN_BL_SUPPORTED = True
except Exception:
    CAN_BL_SUPPORTED = False

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import cantools
from io import BytesIO, StringIO
from datetime import datetime, timedelta
import json
from sklearn.ensemble import IsolationForest
import struct
import re

st.set_page_config(
    page_title="Kinetic Green - CAN Analytics Dashboard",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: var(--primary-color);
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: var(--secondary-background-color);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid var(--primary-color);
    }

    [data-testid="stMetricValue"] {
        color: var(--text-color);
    }

    .stMetric {
        background-color: var(--secondary-background-color);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 12px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)


if 'uploaded_data' not in st.session_state:
    st.session_state.uploaded_data = None
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'dbc_database' not in st.session_state:
    st.session_state.dbc_database = None

def parse_trc(file):
    lines = file.read().decode('utf-8', errors='ignore').splitlines()
    pattern = re.compile(
        r"^\s*\d+\)\s+([\d\.]+)\s+(Rx|Tx)\s+([0-9A-Fa-f]+)\s+\d+\s+((?:[0-9A-Fa-f]{2}\s*)+)"
    )
    data = []
    for line in lines:
        match = pattern.match(line)
        if match:
            timestamp_ms = float(match.group(1))
            can_id = match.group(3).upper()
            data_bytes = match.group(4).strip().split()
            data_hex = ''.join(data_bytes)
            data.append([timestamp_ms / 1000.0, can_id, data_hex])
    df = pd.DataFrame(data, columns=["timestamp", "can_id", "data"])
    return df

def parse_hex_data(hex_string):
    """Parse hex data string to bytes"""
    try:
        hex_string = hex_string.strip().replace(' ', '').replace('0x', '')
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string
        return bytes.fromhex(hex_string)
    except:
        return b'\x00' * 8


def parse_can_csv(file):
    """Parse CAN log in CSV format"""
    try:
        df = pd.read_csv(file)
        df.columns = df.columns.str.lower().str.strip()
        
        if 'time' in df.columns and 'timestamp' not in df.columns:
            df.rename(columns={'time': 'timestamp'}, inplace=True)
        if 'id' in df.columns and 'can_id' not in df.columns:
            df.rename(columns={'id': 'can_id'}, inplace=True)
        if 'msg' in df.columns and 'data' not in df.columns:
            df.rename(columns={'msg': 'data'}, inplace=True)
        
        required_cols = ['timestamp', 'can_id', 'data']
        if not all(col in df.columns for col in required_cols):
            raise ValueError(f"CSV must contain columns: {required_cols}")
        
        return df
    except Exception as e:
        st.error(f"Error parsing CSV: {str(e)}")
        return None


def parse_can_asc(file_content):
    """Parse CAN log in ASC (Vector) format"""
    try:
        lines = file_content.decode('utf-8', errors='ignore').split('\n')
    except:
        lines = file_content.decode('latin-1', errors='ignore').split('\n')
    
    data = []
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('date'):
            continue
        
        parts = line.split()
        if len(parts) >= 7:
            try:
                timestamp = float(parts[0])
                
                can_id = parts[2]
                if can_id.lower().startswith('0x'):
                    can_id = can_id
                else:
                    can_id = f"0x{int(can_id, 16):X}" if can_id.isdigit() else can_id
                
                dlc_idx = 5 if parts[3].lower() == 'rx' or parts[3].lower() == 'tx' else 4
                
                if len(parts) > dlc_idx + 1:
                    msg_bytes = parts[dlc_idx + 1:]
                    msg_data = ' '.join(msg_bytes[:8])
                else:
                    msg_data = ''
                
                data.append({
                    'timestamp': timestamp,
                    'can_id': can_id,
                    'data': msg_data
                })
            except Exception as e:
                continue
    
    return pd.DataFrame(data) if data else None


def parse_can_blf(file_content):
    try:
        import can
        from can import BLFReader
        BLF_AVAILABLE = True
    except Exception:
        BLF_AVAILABLE = False

    if not CAN_BL_SUPPORTED:
        st.warning("BLF parsing is not supported here.")
        return None

    if not BLF_AVAILABLE:
        st.warning("BLF parsing is not supported in this environment.")
        return None

    try:
        blf_file = BytesIO(file_content)
        data = []
        for msg in BLFReader(blf_file):
            data.append({
                "timestamp": msg.timestamp,
                "can_id": f"0x{msg.arbitration_id:X}",
                "data": " ".join(f"{b:02X}" for b in msg.data)
            })
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"BLF parsing failed: {e}")
        return None

def decode_with_dbc(df, dbc_db):
    """Decode CAN messages using DBC database"""
    decoded_data = []
    
    for idx, row in df.iterrows():
        try:
            can_id_int = int(row['can_id'], 16) if isinstance(row['can_id'], str) else int(row['can_id'])
            
            data_bytes = parse_hex_data(str(row['data']))
            
            try:
                message = dbc_db.get_message_by_frame_id(can_id_int)
                decoded = dbc_db.decode_message(can_id_int, data_bytes)
                
                decoded_row = {
                    'timestamp': row['timestamp'],
                    'can_id': row['can_id'],
                    'message_name': message.name,
                    **decoded
                }
                decoded_data.append(decoded_row)
            except KeyError:
                decoded_data.append({
                    'timestamp': row['timestamp'],
                    'can_id': row['can_id'],
                    'message_name': 'Unknown',
                    'raw_data': row['data']
                })
        except Exception as e:
            continue
    
    return pd.DataFrame(decoded_data) if decoded_data else df


def extract_vehicle_parameters_from_decoded(df):
    """Extract vehicle parameters from decoded CAN signals"""
    df = df.copy()
    
    signal_mapping = {
        'battery_voltage': ['battery_voltage', 'batt_volt', 'volt', 'voltage', 'pack_voltage'],
        'battery_current': ['battery_current', 'batt_curr', 'current', 'pack_current'],
        'battery_soc': ['soc', 'state_of_charge', 'battery_soc', 'batt_soc'],
        'battery_temp': ['battery_temp', 'batt_temp', 'pack_temp', 'temperature'],
        'motor_rpm': ['motor_rpm', 'rpm', 'motor_speed', 'speed_rpm'],
        'motor_temp': ['motor_temp', 'motor_temperature', 'inverter_temp'],
        'motor_torque': ['torque', 'motor_torque', 'motor_trq'],
        'vehicle_speed': ['vehicle_speed', 'speed', 'veh_speed', 'velocity'],
        'controller_temp': ['controller_temp', 'inverter_temp', 'ctrl_temp']
    }
    
    for target_param, possible_signals in signal_mapping.items():
        df[target_param] = np.nan
        
        for col in df.columns:
            col_lower = col.lower()
            if any(signal.lower() in col_lower for signal in possible_signals):
                df[target_param] = pd.to_numeric(df[col], errors='coerce')
                break
    
    return df


def extract_vehicle_parameters_heuristic(df):
    """Extract vehicle parameters using heuristic parsing of CAN data"""
    df = df.copy()
    
    params = {
        'battery_voltage': [],
        'battery_current': [],
        'battery_soc': [],
        'battery_temp': [],
        'motor_rpm': [],
        'motor_temp': [],
        'motor_torque': [],
        'vehicle_speed': [],
        'controller_temp': []
    }
    
    for idx, row in df.iterrows():
        row_data = {key: np.nan for key in params.keys()}
        
        try:
            can_id = row['can_id']
            data_bytes = parse_hex_data(str(row['data']))
            
            if len(data_bytes) >= 8:
                if '100' in str(can_id) or '0x100' in str(can_id).lower():
                    row_data['battery_voltage'] = struct.unpack('>H', data_bytes[0:2])[0] / 10.0
                    row_data['battery_current'] = struct.unpack('>h', data_bytes[2:4])[0] / 10.0
                
                elif '200' in str(can_id) or '0x200' in str(can_id).lower():
                    row_data['battery_soc'] = data_bytes[0]
                    row_data['battery_temp'] = data_bytes[1] - 40
                
                elif '300' in str(can_id) or '0x300' in str(can_id).lower():
                    row_data['motor_rpm'] = struct.unpack('>H', data_bytes[0:2])[0]
                    row_data['motor_torque'] = struct.unpack('>H', data_bytes[2:4])[0] / 10.0
                
                elif '400' in str(can_id) or '0x400' in str(can_id).lower():
                    row_data['vehicle_speed'] = struct.unpack('>H', data_bytes[0:2])[0] / 100.0
                    row_data['motor_temp'] = data_bytes[2] - 40
                    row_data['controller_temp'] = data_bytes[2] - 40 - 5
        
        except Exception as e:
            pass
        
        for key in params.keys():
            params[key].append(row_data[key])
    
    for key, values in params.items():
        df[key] = values
    
    return df


def clean_and_process_data(df, dbc_db=None):
    """Clean and process CAN log data"""
    if df is None or df.empty:
        return None
    
    df = df.copy()
    
    if 'timestamp' in df.columns:
        if df['timestamp'].dtype == 'object':
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            except:
                df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        
        if pd.api.types.is_numeric_dtype(df['timestamp']):
            base_time = datetime.now() - timedelta(hours=1)
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
            if df['datetime'].isna().all():
                df['datetime'] = base_time + pd.to_timedelta(df['timestamp'], unit='s')
        else:
            df['datetime'] = df['timestamp']
    
    df = df.dropna(subset=['timestamp'])
    
    if 'can_id' in df.columns:
        df['can_id'] = df['can_id'].astype(str)
    
    if dbc_db is not None:
        df = decode_with_dbc(df, dbc_db)
        df = extract_vehicle_parameters_from_decoded(df)
    else:
        df = extract_vehicle_parameters_heuristic(df)
    
    required_params = ['battery_voltage', 'battery_current', 'battery_soc', 'battery_temp', 
                      'motor_rpm', 'motor_temp', 'motor_torque', 'vehicle_speed', 'controller_temp']
    
    for param in required_params:
        if param not in df.columns:
            df[param] = np.nan
    
    for param in required_params:
        if param in df.columns:
            df[param] = df[param].fillna(method='ffill').fillna(method='bfill')
    
    return df


def detect_anomalies(df, column):
    """Detect anomalies using Isolation Forest"""
    if column not in df.columns or df[column].isna().all():
        return np.zeros(len(df))
    
    data = df[[column]].fillna(df[column].mean())
    
    iso_forest = IsolationForest(contamination=0.05, random_state=42)
    anomalies = iso_forest.fit_predict(data)
    
    return anomalies


st.markdown('<div class="main-header">⚡ Kinetic Green - CAN Analytics Dashboard</div>', unsafe_allow_html=True)

st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["📤 Upload Data", "📊 Dashboard", "📈 Analytics", "💾 Export Data"])

if page == "📤 Upload Data":
    st.header("📤 CAN Log File Upload")
    st.markdown("Upload your CAN log files and optionally a DBC file for signal decoding")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Step 1: Upload DBC File (Optional)")
        dbc_file = st.file_uploader(
            "Upload DBC file for signal decoding",
            type=['dbc'],
            help="DBC file contains CAN message definitions and signal mappings"
        )

        if dbc_file is not None:
            try:
                dbc_content = dbc_file.read().decode("utf-8", errors="ignore")
                dbc_temp = StringIO(dbc_content)
                st.session_state.dbc_database = cantools.database.load(
                    dbc_temp,
                    database_format='dbc'
                )
                st.success(f"✅ DBC file loaded: {len(st.session_state.dbc_database.messages)} messages defined")

            except Exception as e:
                st.error(f"Error loading DBC file: {str(e)}")
                st.session_state.dbc_database = None

        st.markdown("---")
        
        st.subheader("Step 2: Upload CAN Log File")
        
        file_format = st.selectbox(
            "Select File Format",
            ["CSV", "ASC (Vector)", "BLF (Binary)", "JSON", "TRC", "PARQUET"]
        )
        
        uploaded_file = st.file_uploader(
            f"Choose a {file_format} file",
            type=['csv', 'asc', 'blf', 'json', 'txt',
                  'log', 'trc', 'parquet'],
            help="Upload CAN log files for processing"
        )
        
        if uploaded_file is not None:
            st.success(f"✅ File uploaded: {uploaded_file.name}")
            with st.spinner("Processing CAN log data..."):
                if file_format == "CSV":
                    raw_df = parse_can_csv(uploaded_file)
                elif file_format == "ASC (Vector)":
                    raw_df = parse_can_asc(uploaded_file.read())
                elif file_format == "BLF (Binary)":
                    raw_df = parse_can_blf(uploaded_file.read())
                elif uploaded_file.name.endswith(".parquet"):
                    raw_df = pd.read_parquet(uploaded_file)
                elif uploaded_file.name.endswith(".trc"):
                    raw_df = parse_trc(uploaded_file)
                elif file_format == "JSON":
                    try:
                        data = json.load(uploaded_file)
                        raw_df = pd.DataFrame(data)
                    except Exception as e:
                        st.error(f"Invalid JSON format: {str(e)}")
                        raw_df = None
                
                if raw_df is not None and not raw_df.empty:
                    st.session_state.uploaded_data = raw_df
                    st.session_state.processed_data = clean_and_process_data(
                        raw_df, 
                        st.session_state.dbc_database
                    )
                    
                    st.success("✅ Data processed successfully!")
                    
                    st.subheader("Raw Data Preview")
                    st.dataframe(st.session_state.uploaded_data.head(100), height=200)
                    
                    st.subheader("Processed Data Preview (with extracted parameters)")
                    st.dataframe(st.session_state.processed_data.head(100), height=200)
                    
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Total Records", len(st.session_state.processed_data))
                    with col_b:
                        st.metric("Unique CAN IDs", st.session_state.uploaded_data['can_id'].nunique())
                    with col_c:
                        duration = st.session_state.uploaded_data['timestamp'].max() - st.session_state.uploaded_data['timestamp'].min()
                        st.metric("Duration (s)", f"{duration:.2f}")
                    
                    if st.session_state.dbc_database:
                        st.info(f"📋 Using DBC database with {len(st.session_state.dbc_database.messages)} message definitions")
                    else:
                        st.info("📋 Using heuristic CAN ID-based parameter extraction from message bytes")
                else:
                    st.error("Failed to parse the uploaded file. Please check the format.")
    
    with col2:
        st.info("""
        **Supported Formats:**
        - CSV: timestamp, can_id, data
        - ASC: Vector ASCII format
        - BLF: Binary log format
        - JSON: Array of CAN messages
        - TRC: Vector TRC format
        - PARQUET: Parquet format
        
        **DBC File:**
        Upload a DBC file to decode CAN signals from message bytes. Without DBC, heuristic extraction parses known CAN IDs.
        
        **CAN IDs for heuristic mode:**
        - 0x100: Battery voltage/current
        - 0x200: SOC, temperature
        - 0x300: Motor RPM, torque
        - 0x400: Vehicle speed, motor temp
        """)

elif page == "📊 Dashboard":
    st.header("📊 Vehicle Analytics Dashboard")
    
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload CAN log data first")
        st.info("Navigate to '📤 Upload Data' to get started")
    else:
        df = st.session_state.processed_data
        
        st.subheader("Key Performance Indicators")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            avg_soc = df['battery_soc'].mean()
            soc_change = df['battery_soc'].iloc[-1] - df['battery_soc'].iloc[0] if len(df) > 1 else 0
            st.metric("Avg Battery SOC", f"{avg_soc:.1f}%", 
                     delta=f"{soc_change:.1f}%")
        
        with col2:
            avg_speed = df['vehicle_speed'].mean()
            st.metric("Avg Speed", f"{avg_speed:.1f} km/h")
        
        with col3:
            max_temp = df['battery_temp'].max()
            st.metric("Max Battery Temp", f"{max_temp:.1f}°C")
        
        with col4:
            avg_rpm = df['motor_rpm'].mean()
            st.metric("Avg Motor RPM", f"{avg_rpm:.0f}")
        
        st.markdown("---")
        
        tab1, tab2, tab3 = st.tabs(["Battery Metrics", "Motor Performance", "Temperature Analysis"])
        
        with tab1:
            col1, col2 = st.columns(2)
            
            with col1:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['battery_soc'],
                    mode='lines',
                    name='SOC (%)',
                    line=dict(color='#1E8449', width=2)
                ))
                fig.update_layout(
                    title="Battery State of Charge Over Time",
                    xaxis_title="Sample Index",
                    yaxis_title="SOC (%)",
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['battery_voltage'],
                    mode='lines',
                    name='Voltage (V)',
                    line=dict(color='#2874A6', width=2)
                ))
                fig.update_layout(
                    title="Battery Voltage",
                    xaxis_title="Sample Index",
                    yaxis_title="Voltage (V)",
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df.index,
                y=df['battery_current'],
                mode='lines',
                name='Current (A)',
                line=dict(color='#D68910', width=2),
                fill='tozeroy'
            ))
            fig.update_layout(
                title="Battery Current (Charge/Discharge)",
                xaxis_title="Sample Index",
                yaxis_title="Current (A)",
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            col1, col2 = st.columns(2)
            
            with col1:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['motor_rpm'],
                    mode='lines',
                    name='RPM',
                    line=dict(color='#8E44AD', width=2)
                ))
                fig.update_layout(
                    title="Motor RPM",
                    xaxis_title="Sample Index",
                    yaxis_title="RPM",
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['motor_torque'],
                    mode='lines',
                    name='Torque (Nm)',
                    line=dict(color='#C0392B', width=2)
                ))
                fig.update_layout(
                    title="Motor Torque",
                    xaxis_title="Sample Index",
                    yaxis_title="Torque (Nm)",
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            
            fig = px.scatter(
                df,
                x='motor_rpm',
                y='motor_torque',
                color='vehicle_speed',
                title="Motor Performance Map (RPM vs Torque)",
                labels={'motor_rpm': 'RPM', 'motor_torque': 'Torque (Nm)', 'vehicle_speed': 'Speed (km/h)'},
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            col1, col2 = st.columns(2)
            
            with col1:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['battery_temp'],
                    mode='lines',
                    name='Battery Temp',
                    line=dict(color='#E74C3C', width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['motor_temp'],
                    mode='lines',
                    name='Motor Temp',
                    line=dict(color='#F39C12', width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=df.index,
                    y=df['controller_temp'],
                    mode='lines',
                    name='Controller Temp',
                    line=dict(color='#16A085', width=2)
                ))
                fig.update_layout(
                    title="Temperature Monitoring",
                    xaxis_title="Sample Index",
                    yaxis_title="Temperature (°C)",
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                temp_data = pd.DataFrame({
                    'Component': ['Battery', 'Motor', 'Controller'],
                    'Avg Temp': [
                        df['battery_temp'].mean(),
                        df['motor_temp'].mean(),
                        df['controller_temp'].mean()
                    ],
                    'Max Temp': [
                        df['battery_temp'].max(),
                        df['motor_temp'].max(),
                        df['controller_temp'].max()
                    ]
                })
                
                fig = go.Figure(data=[
                    go.Bar(name='Average', x=temp_data['Component'], y=temp_data['Avg Temp']),
                    go.Bar(name='Maximum', x=temp_data['Component'], y=temp_data['Max Temp'])
                ])
                fig.update_layout(
                    title="Temperature Summary by Component",
                    yaxis_title="Temperature (°C)",
                    barmode='group',
                    height=350
                )
                st.plotly_chart(fig, use_container_width=True)

elif page == "📈 Analytics":
    st.header("📈 Advanced Analytics & Insights")
    
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload CAN log data first")
        st.info("Navigate to '📤 Upload Data' to get started")
    else:
        df = st.session_state.processed_data
        
        st.subheader("Statistical Summary")
        
        metrics_to_analyze = ['battery_soc', 'battery_voltage', 'motor_rpm', 'vehicle_speed', 'battery_temp']
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            selected_metric = st.selectbox(
                "Select Metric for Analysis",
                metrics_to_analyze,
                format_func=lambda x: x.replace('_', ' ').title()
            )
        
        with col2:
            filter_range = st.slider(
                "Data Range (%)",
                0, 100, (0, 100),
                help="Filter data by percentage of total records"
            )
        
        start_idx = int(len(df) * filter_range[0] / 100)
        end_idx = int(len(df) * filter_range[1] / 100)
        filtered_df = df.iloc[start_idx:end_idx]
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Mean", f"{filtered_df[selected_metric].mean():.2f}")
        with col2:
            st.metric("Median", f"{filtered_df[selected_metric].median():.2f}")
        with col3:
            st.metric("Std Dev", f"{filtered_df[selected_metric].std():.2f}")
        with col4:
            st.metric("Min", f"{filtered_df[selected_metric].min():.2f}")
        with col5:
            st.metric("Max", f"{filtered_df[selected_metric].max():.2f}")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.histogram(
                filtered_df,
                x=selected_metric,
                nbins=50,
                title=f"Distribution of {selected_metric.replace('_', ' ').title()}",
                color_discrete_sequence=['#1E8449']
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.box(
                filtered_df,
                y=selected_metric,
                title=f"Box Plot - {selected_metric.replace('_', ' ').title()}",
                color_discrete_sequence=['#2874A6']
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Anomaly Detection")
        
        anomaly_metric = st.selectbox(
            "Select Metric for Anomaly Detection",
            metrics_to_analyze,
            format_func=lambda x: x.replace('_', ' ').title(),
            key='anomaly_metric'
        )
        
        anomalies = detect_anomalies(filtered_df, anomaly_metric)
        anomaly_df = filtered_df.copy()
        anomaly_df['is_anomaly'] = anomalies == -1
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            fig = go.Figure()
            
            normal_data = anomaly_df[~anomaly_df['is_anomaly']]
            anomaly_data = anomaly_df[anomaly_df['is_anomaly']]
            
            fig.add_trace(go.Scatter(
                x=normal_data.index,
                y=normal_data[anomaly_metric],
                mode='markers',
                name='Normal',
                marker=dict(color='#1E8449', size=5)
            ))
            
            fig.add_trace(go.Scatter(
                x=anomaly_data.index,
                y=anomaly_data[anomaly_metric],
                mode='markers',
                name='Anomaly',
                marker=dict(color='#E74C3C', size=10, symbol='x')
            ))
            
            fig.update_layout(
                title=f"Anomaly Detection - {anomaly_metric.replace('_', ' ').title()}",
                xaxis_title="Sample Index",
                yaxis_title=anomaly_metric.replace('_', ' ').title(),
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            anomaly_count = anomaly_df['is_anomaly'].sum()
            anomaly_percentage = (anomaly_count / len(anomaly_df)) * 100
            
            st.metric("Total Anomalies", anomaly_count)
            st.metric("Anomaly Rate", f"{anomaly_percentage:.2f}%")
            
            if anomaly_count > 0:
                st.warning(f"⚠️ {anomaly_count} anomalies detected")
            else:
                st.success("✅ No anomalies detected")
        
        st.markdown("---")
        
        st.subheader("Correlation Analysis")
        
        correlation_metrics = ['battery_soc', 'battery_voltage', 'battery_current', 'motor_rpm', 'vehicle_speed', 'battery_temp']
        corr_matrix = filtered_df[correlation_metrics].corr()
        
        fig = px.imshow(
            corr_matrix,
            text_auto='.2f',
            aspect='auto',
            title='Correlation Matrix of Vehicle Parameters',
            color_continuous_scale='RdYlGn',
            zmin=-1,
            zmax=1
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Business Insights")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔋 Battery Health Insights")
            avg_soc = df['battery_soc'].mean()
            min_soc = df['battery_soc'].min()
            
            if avg_soc > 70:
                st.success(f"✅ Good battery health - Average SOC: {avg_soc:.1f}%")
            elif avg_soc > 40:
                st.warning(f"⚠️ Moderate battery usage - Average SOC: {avg_soc:.1f}%")
            else:
                st.error(f"❌ High battery drain - Average SOC: {avg_soc:.1f}%")
            
            if min_soc < 20:
                st.warning(f"⚠️ Battery dropped to {min_soc:.1f}% - Consider charging infrastructure improvements")
            
            temp_violations = (df['battery_temp'] > 50).sum()
            if temp_violations > 0:
                st.warning(f"⚠️ Battery temperature exceeded 50°C in {temp_violations} instances")
        
        with col2:
            st.markdown("### ⚙️ Motor Performance Insights")
            avg_rpm = df['motor_rpm'].mean()
            max_rpm = df['motor_rpm'].max()
            
            st.info(f"📊 Average motor RPM: {avg_rpm:.0f}")
            st.info(f"📊 Peak motor RPM: {max_rpm:.0f}")
            
            high_load_time = (df['motor_torque'] > 80).sum() / len(df) * 100
            if high_load_time > 30:
                st.warning(f"⚠️ High torque load for {high_load_time:.1f}% of the time - Monitor motor wear")
            else:
                st.success(f"✅ Moderate motor load - {high_load_time:.1f}% high torque usage")

elif page == "💾 Export Data":
    st.header("💾 Export Processed Data")
    
    if st.session_state.processed_data is None:
        st.warning("⚠️ Please upload and process CAN log data first")
        st.info("Navigate to '📤 Upload Data' to get started")
    else:
        df = st.session_state.processed_data
        
        st.subheader("Export Options")
        
        col1, col2 = st.columns(2)
        
        with col1:
            export_format = st.radio(
                "Select Export Format",
                ["CSV", "Excel (XLSX)", "JSON"]
            )
        
        with col2:
            include_stats = st.checkbox("Include Statistical Summary", value=True)
            include_all_columns = st.checkbox("Include All Columns", value=True)
        
        if not include_all_columns:
            selected_columns = st.multiselect(
                "Select Columns to Export",
                df.columns.tolist(),
                default=['timestamp', 'battery_soc', 'vehicle_speed', 'battery_temp']
            )
            export_df = df[selected_columns] if selected_columns else df
        else:
            export_df = df
        
        st.subheader("Data Preview")
        st.dataframe(export_df.head(50), height=300)
        
        st.markdown("---")
        
        if export_format == "CSV":
            csv = export_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"kinetic_green_can_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        elif export_format == "Excel (XLSX)":
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                export_df.to_excel(writer, sheet_name='CAN Data', index=False)
                
                if include_stats:
                    stats_df = export_df.describe()
                    stats_df.to_excel(writer, sheet_name='Statistics')
            
            output.seek(0)
            st.download_button(
                label="📥 Download Excel",
                data=output,
                file_name=f"kinetic_green_can_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        
        elif export_format == "JSON":
            json_data = export_df.to_json(orient='records', date_format='iso')
            st.download_button(
                label="📥 Download JSON",
                data=json_data,
                file_name=f"kinetic_green_can_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )


        
        st.markdown("---")
        
        st.subheader("📊 Export Summary")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Records", len(export_df))
        with col2:
            st.metric("Total Columns", len(export_df.columns))
        with col3:
            file_size_mb = export_df.memory_usage(deep=True).sum() / (1024 * 1024)
            st.metric("Approx. Size", f"{file_size_mb:.2f} MB")

st.sidebar.markdown("---")
st.sidebar.info("""
**Kinetic Green Analytics**

Version: 2.0.0

Analyze CAN bus logs from EV vehicles. Upload DBC files for accurate signal decoding or use heuristic extraction.

**Features:**
- Multi-format support
- DBC signal decoding
- Real-time analytics
- Export capabilities
""")
