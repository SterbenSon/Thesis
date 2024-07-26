import React, { useState, useEffect } from 'react';
import axios from 'axios';
import CircularProgress from '@mui/material/CircularProgress';
import { Container, Button, Typography, TextField, Box, Paper, Drawer, List, ListItem, ListItemText, Divider, ListItemIcon, IconButton, Tooltip, LinearProgress } from '@mui/material';
import { InsertDriveFile, History, Home, Info, HelpOutline } from '@mui/icons-material';
import './App.css'; 
import headerImage from './cyber.jpg';

const App = () => {
  const [file, setFile] = useState(null);
  const [downloadUrl, setDownloadUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [currentTab, setCurrentTab] = useState('scan');
  const [showInfo, setShowInfo] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const savedHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
    setHistory(savedHistory);
  }, []);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    const allowedTypes = ['video/mp4', 'video/avi', 'video/mkv', 'audio/mp3', 'audio/wav', 'audio/flac', 'video/mov', 'video/wmv', 'image/jpeg', 'image/png', 'image/gif'];
    if (selectedFile && allowedTypes.includes(selectedFile.type)) {
      setFile(selectedFile);
      setError('');
    } else {
      setFile(null);
      setError('File should be a multimedia file (mp4, avi, mkv, mp3, wav, flac, mov, wmv, jpg, jpeg, png, gif)');
    }
  };

  const handleUrlChange = (e) => {
    const url = e.target.value;
    setDownloadUrl(url);

    const urlPattern = new RegExp('^(https?:\\/\\/)?' + 
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.?)+[a-z]{2,}|' + 
      '((\\d{1,3}\\.){3}\\d{1,3}))' + 
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + 
      '(\\?[;&a-z\\d%_.~+=-]*)?' + 
      '(\\#[-a-z\\d_]*)?$', 'i'); 

    if (!urlPattern.test(url)) {
      setError('Please enter a valid URL');
    } else {
      setError('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      alert('Please upload a file');
      return;
    }
    if (!downloadUrl) {
      alert('Please provide a download URL');
      return;
    }
    setIsLoading(true);
    setProgress(0); 
    startProgress(); 
    const formData = new FormData();
    formData.append('file', file);
    formData.append('download_url', downloadUrl);

    try {
      const response = await axios.post('http://192.168.179.129:5000/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      const responseData = { ...response.data, scan_date: new Date().toISOString(), file_name: file.name };
      updateResultsGradually(responseData);
      const updatedHistory = [responseData, ...history];
      setHistory(updatedHistory);
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error uploading file');
    } finally {
      setIsLoading(false);
      setProgress(100);
    }
  };

  const startProgress = () => {
    const updateIntervals = [1000, 3000, 7000, 16000];
    const increments = [3, 5, 7];
    let elapsedTime = 0;
  
    
    let timeIncrement = updateIntervals[Math.floor(Math.random() * updateIntervals.length)];
  
    const interval = setInterval(() => {
      timeIncrement = updateIntervals[Math.floor(Math.random() * updateIntervals.length)];
      const progressIncrement = increments[Math.floor(Math.random() * increments.length)];
  
      setProgress(prevProgress => {
        const newProgress = prevProgress + progressIncrement;
        if (newProgress >= 100 || elapsedTime >= 100000) {
          clearInterval(interval);
          return 100;
        }
        return newProgress;
      });
  
      elapsedTime += timeIncrement;
    }, timeIncrement);
  };

  const getResultText = (result) => {
    if (!result || !result.malicious) {
      return <span style={{ color: 'green' }}>Detected as safe</span>;
    }
    return <span style={{ color: 'red' }}>Detected as malware</span>;
  };

  const getEntropyText = (entropy) => {
    return entropy > 7 ? (
      <span style={{ color: 'red' }}>High entropy, potentially compressed or encrypted content</span>
    ) : (
      <span style={{ color: 'green' }}>Normal entropy</span>
    );
  };

  const renderResults = () => {
    if (!results || results.final_score === undefined) return null;

    const scoreColor = results.final_score > 65 ? 'green' : results.final_score > 35 ? 'orange' : 'red';

    return (
      <Paper elevation={3} className="results-paper">
        <Typography className="results-title">Analysis Results</Typography>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Typography variant="h4" className="final-score" style={{ color: scoreColor }}>
            Analysis Score: {results.final_score !== undefined ? results.final_score.toFixed(2) : 'N/A'} / 100
          </Typography>
          <Tooltip title="Click for more info" placement="top">
            <IconButton onClick={() => setShowInfo(!showInfo)}>
              <HelpOutline />
            </IconButton>
          </Tooltip>
        </Box>
        {showInfo && (
          <Paper elevation={3} className="info-paper">
            <Typography variant="body2">The score is calculated based on various factors including:</Typography>
            <ul>
              <li>VirusTotal detections: This has the most weight because it aggregates results from multiple antivirus engines.</li>
              <li>MetaDefender detections: This is important as it provides additional verification from another set of antivirus engines.</li>
              <li>ClamAV results: Provides an additional layer of scanning with an open-source antivirus engine.</li>
              <li>YARA results: Detects specific malware signatures.</li>
              <li>URL reputation: Checks the safety of the URL where the file was downloaded from.</li>
              <li>Metadata analysis: Factors like file size and entropy provide insights into the nature of the file.</li>
              <li>IP fraud score: Indicates the likelihood of the IP address being associated with malicious activity.</li>
            </ul>
          </Paper>
        )}
        <Typography variant="h5" style={{ color: scoreColor }}>
          {results.final_score > 65 ? 'File is safe' : results.final_score > 35 ? 'File is suspicious' : 'File is malicious'}
        </Typography>
        <Typography variant="body1">Duration: {results.duration} seconds</Typography>
        <Box className="score-indicator">
          <Box className="score-bar">
            <Box className="indicator" style={{ left: `${results.final_score}%`, backgroundColor: 'black', width: '4px' }} />
          </Box>
          <Box className="score-labels">
            <Typography variant="body2" style={{ color: 'red' }}>Malicious</Typography>
            <Typography variant="body2" style={{ color: 'orange' }}>Suspicious</Typography>
            <Typography variant="body2" style={{ color: 'green' }}>Safe</Typography>
          </Box>
        </Box>
        <Typography className="results-title">VirusTotal Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{results.vt_results ? getResultText(results.vt_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">MetaDefender Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{results.md_results ? getResultText(results.md_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">ClamAV Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{results.clamav_results ? getResultText(results.clamav_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">YARA Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li style={{ color: results.yara_results && results.yara_results.malicious > 0 ? 'red' : 'green', fontWeight: 'bold' }}>
            {results.yara_results && results.yara_results.malicious > 0 ? 
              `Detected as malware: ${results.yara_results.malicious_details.join(', ')}` : 
              'Detected as safe'}
          </li>
        </Typography>
        <Typography className="results-title">URL Reputation:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{results.url_reputation_score === 'url is not safe' ? <span style={{ color: 'red' }}>URL is not safe</span> : <span style={{ color: 'green' }}>Clean</span>}</li>
        </Typography>
        <Typography className="results-title">Metadata Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          {results.metadata_analysis ? Object.entries(results.metadata_analysis).map(([key, value]) => (
            <li key={key}>{key}: {value}</li>
          )) : 'N/A'}
        </Typography>
        <Typography className="results-title">Historical Data:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Previously Seen: {results.historical_data ? (results.historical_data.previously_seen ? 'Yes' : 'No') : 'N/A'}</li>
          <li>Times Seen: {results.historical_data ? results.historical_data.times_seen : 'N/A'}</li>
          <li>First Seen: {results.historical_data ? results.historical_data.first_seen : 'N/A'}</li>
          <li>Last Seen: {results.historical_data ? results.historical_data.last_seen : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">Entropy:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{results.entropy !== undefined ? getEntropyText(results.entropy) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">IP Fraud Score:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li style={{ color: results.ip_fraud_score > 70 ? 'red' : 'black' }}>{results.ip_fraud_score !== undefined ? results.ip_fraud_score : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">Behavioral Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Execution Behavior: {results.behavioral_analysis?.execution_behavior ? 'Detected' : 'Not Detected'}</li>
          <li>File System Changes Detected: {results.behavioral_analysis?.fs_changes_detected ? 'Yes' : 'No'}</li>
        </Typography>
      </Paper>
    );
  };

  const renderHistory = () => {
    if (!history.length) return <Typography>No scan history available.</Typography>;
  
    return history.map((item, index) => (
      <Paper key={index} elevation={3} className="results-paper">
        <Typography className="results-title">Analysis Results</Typography>
        <Typography variant="h4" className="final-score" style={{ color: item.final_score > 65 ? 'green' : item.final_score > 35 ? 'orange' : 'red' }}>
          Average Threat Score: {item.final_score.toFixed(2)}
        </Typography>
        <Typography variant="h5" style={{ color: item.final_score > 65 ? 'green' : item.final_score > 35 ? 'orange' : 'red' }}>
          {item.final_score > 65 ? 'File is safe' : item.final_score > 35 ? 'File is suspicious' : 'File is malicious'}
        </Typography>
        <Typography variant="body1">Duration: {item.duration} seconds</Typography>
        <Typography variant="h6" style={{ fontWeight: 'bold', color: 'blue' }}>Scan Date: {new Date(item.scan_date).toLocaleDateString()}</Typography>
        <Typography variant="h6" style={{ fontWeight: 'bold', color: 'blue' }}>File Name: {item.file_name}</Typography>
  
        <Typography className="results-title">VirusTotal Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.vt_results ? getResultText(item.vt_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">MetaDefender Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.md_results ? getResultText(item.md_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">ClamAV Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.clamav_results ? getResultText(item.clamav_results) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">YARA Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.yara_results && item.yara_results.malicious > 0 ? `Detected as malware: ${item.yara_results.malicious_details.join(', ')}` : 'Detected as safe'}</li>
        </Typography>
        <Typography className="results-title">URL Reputation:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.url_reputation_score === 'url is not safe' ? <span style={{ color: 'red' }}>URL is not safe</span> : <span style={{ color: 'green' }}>Clean</span>}</li>
        </Typography>
        <Typography className="results-title">Metadata Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          {item.metadata_analysis ? Object.entries(item.metadata_analysis).map(([key, value]) => (
            <li key={key}>{key}: {value}</li>
          )) : 'N/A'}
        </Typography>
        <Typography className="results-title">Historical Data:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Previously Seen: {item.historical_data ? (item.historical_data.previously_seen ? 'Yes' : 'No') : 'N/A'}</li>
          <li>Times Seen: {item.historical_data ? item.historical_data.times_seen : 'N/A'}</li>
          <li>First Seen: {item.historical_data ? item.historical_data.first_seen : 'N/A'}</li>
          <li>Last Seen: {item.historical_data ? item.historical_data.last_seen : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">Entropy:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>{item.entropy !== undefined ? getEntropyText(item.entropy) : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">IP Fraud Score:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li style={{ color: item.ip_fraud_score > 70 ? 'red' : 'black' }}>{item.ip_fraud_score !== undefined ? item.ip_fraud_score : 'N/A'}</li>
        </Typography>
        <Typography className="results-title">Behavioral Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Execution Behavior: {item.behavioral_analysis?.execution_behavior ? 'Detected' : 'Not Detected'}</li>
          <li>File System Changes Detected: {item.behavioral_analysis?.fs_changes_detected ? 'Yes' : 'No'}</li>
        </Typography>
      </Paper>
    ));
  };
  
  const updateResultsGradually = (newResults) => {
    const updateInterval = 500; 
    let partialResults = {};
  
    const keys = Object.keys(newResults);
    keys.forEach((key, index) => {
      setTimeout(() => {
        partialResults = { ...partialResults, [key]: newResults[key] };
        setResults(partialResults);
      }, index * updateInterval);
    });
  };
  
  return (
    <Box sx={{ display: 'flex' }}>
      <Drawer
        variant="permanent"
        anchor="left"
        className="sidebar"
      >
        <List>
          <ListItem button onClick={() => setCurrentTab('scan')}>
            <ListItemIcon><InsertDriveFile /></ListItemIcon>
            <ListItemText primary="Scan File" />
          </ListItem>
          <ListItem button onClick={() => setCurrentTab('history')}>
            <ListItemIcon><History /></ListItemIcon>
            <ListItemText primary="Scan History" />
          </ListItem>
          <Divider />
          <ListItem button onClick={() => setCurrentTab('scan')}>
            <ListItemIcon><Home /></ListItemIcon>
            <ListItemText primary="Home" />
          </ListItem>
          <ListItem button>
            <ListItemIcon><Info /></ListItemIcon>
            <ListItemText primary="About" />
          </ListItem>
        </List>
        <Divider />
        <Typography variant="body2" align="center" style={{ padding: '16px' }}>
          &copy; CS2 Scanner
        </Typography>
      </Drawer>
      <Container className="container">
        {currentTab === 'scan' && (
          <>
            <Box className="header" sx={{ backgroundImage: `url(${headerImage})` }}>
              <Typography className="title" variant="h4" gutterBottom>
                Minos Scanner
              </Typography>
            </Box>
            <form onSubmit={handleSubmit} className="upload-form">
              <input type="file" onChange={handleFileChange} className="file-input" />
              {error && <Typography variant="body2" className="error-message">{error}</Typography>}
              <TextField
                label="Enter where you have downloaded the file from"
                value={downloadUrl}
                onChange={handleUrlChange}
                fullWidth
                margin="normal"
                InputLabelProps={{
                  style: { color: '#000000', fontWeight: 'bold' }
                }}
                InputProps={{
                  style: { color: '#000000' }
                }}
              />
              <Button type="submit" variant="contained" color="primary" disabled={isLoading || !file || !downloadUrl || error}>
                Upload and Scan
              </Button>
            </form>
            {isLoading && (
              <Box mt={2}>
                <CircularProgress />
                <Typography variant="body1" style={{ marginLeft: '10px', color: '#000000' }}>
                  Scanning...
                </Typography>
                <LinearProgress variant="determinate" value={progress} />
              </Box>
            )}
            {renderResults()}
          </>
        )}
        {currentTab === 'history' && (
          <>
            <Typography className="title" variant="h4" gutterBottom>
              Scan History
            </Typography>
            {renderHistory()}
          </>
        )}
      </Container>
    </Box>
  );
  };
  
  export default App;
  
