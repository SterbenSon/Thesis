import React, { useState, useEffect } from 'react';
import axios from 'axios';
import CircularProgress from '@mui/material/CircularProgress';
import { Container, Button, Typography, TextField, Box, Paper, Drawer, List, ListItem, ListItemText, Divider, ListItemIcon } from '@mui/material';
import { InsertDriveFile, History, Settings, Home, Info, HomeMaxOutlined } from '@mui/icons-material';
import './App.css'; 

const App = () => {
  const [file, setFile] = useState(null);
  const [downloadUrl, setDownloadUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [currentTab, setCurrentTab] = useState('scan');

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
    setDownloadUrl(e.target.value);
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
    const formData = new FormData();
    formData.append('file', file);
    formData.append('download_url', downloadUrl);

    try {
      const response = await axios.post('http://192.168.179.130:5000/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setResults(response.data);
      const updatedHistory = [response.data, ...history];
      setHistory(updatedHistory);
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error uploading file');
    } finally {
      setIsLoading(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    return (
      <Paper elevation={3} className="results-paper">
        <Typography className="results-title">Analysis Results</Typography>
        <Typography variant="body1">Average Threat Score: {results.final_score.toFixed(2)}</Typography>
        <Typography variant="body1">Duration: {results.duration} seconds</Typography>
        <Typography className="results-title">VirusTotal Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {results.vt_results.malicious}</li>
          <li>Suspicious: {results.vt_results.suspicious}</li>
          <li>Undetected: {results.vt_results.undetected}</li>
          <li>Harmless: {results.vt_results.harmless}</li>
        </Typography>
        <Typography className="results-title">MetaDefender Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {results.md_results.malicious}</li>
          <li>Harmless: {results.md_results.harmless}</li>
          <li>Undetected: {results.md_results.undetected}</li>
        </Typography>
        <Typography className="results-title">ClamAV Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {results.clamav_results.malicious}</li>
          <li>Harmless: {results.clamav_results.harmless}</li>
          <li>Undetected: {results.clamav_results.undetected}</li>
        </Typography>
        <Typography className="results-title">YARA Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {results.yara_results.malicious}</li>
          <li>Harmless: {results.yara_results.harmless}</li>
        </Typography>
        <Typography className="results-title">URL Reputation Score: {results.url_reputation_score}</Typography>
        <Typography className="results-title">Metadata Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Creation Date: {results.metadata_analysis.creation_date}</li>
          <li>Modification Date: {results.metadata_analysis.modification_date}</li>
          <li>File Age (days): {results.metadata_analysis.file_age_days}</li>
        </Typography>
        <Typography className="results-title">Historical Data:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Previously Seen: {results.historical_data.previously_seen ? 'Yes' : 'No'}</li>
          <li>Times Seen: {results.historical_data.times_seen}</li>
          <li>First Seen: {results.historical_data.first_seen}</li>
          <li>Last Seen: {results.historical_data.last_seen}</li>
        </Typography>
      </Paper>
    );
  };

  const renderHistory = () => {
    if (!history.length) return <Typography>No scan history available.</Typography>;

    return history.map((item, index) => (
      <Paper key={index} elevation={3} className="results-paper">
        <Typography className="results-title">Analysis Results</Typography>
        <Typography variant="body1">Average Threat Score: {item.final_score.toFixed(2)}</Typography>
        <Typography variant="body1">Duration: {item.duration} seconds</Typography>
        <Typography className="results-title">VirusTotal Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {item.vt_results.malicious}</li>
          <li>Suspicious: {item.vt_results.suspicious}</li>
          <li>Undetected: {item.vt_results.undetected}</li>
          <li>Harmless: {item.vt_results.harmless}</li>
        </Typography>
        <Typography className="results-title">MetaDefender Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {item.md_results.malicious}</li>
          <li>Harmless: {item.md_results.harmless}</li>
          <li>Undetected: {item.md_results.undetected}</li>
        </Typography>
        <Typography className="results-title">ClamAV Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {item.clamav_results.malicious}</li>
          <li>Harmless: {item.clamav_results.harmless}</li>
          <li>Undetected: {item.clamav_results.undetected}</li>
        </Typography>
        <Typography className="results-title">YARA Results:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Malicious: {item.yara_results.malicious}</li>
          <li>Harmless: {item.yara_results.harmless}</li>
        </Typography>
        <Typography className="results-title">URL Reputation Score: {item.url_reputation_score}</Typography>
        <Typography className="results-title">Metadata Analysis:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Creation Date: {item.metadata_analysis.creation_date}</li>
          <li>Modification Date: {item.metadata_analysis.modification_date}</li>
          <li>File Age (days): {item.metadata_analysis.file_age_days}</li>
        </Typography>
        <Typography className="results-title">Historical Data:</Typography>
        <Typography variant="body2" component="ul" className="results-list">
          <li>Previously Seen: {item.historical_data.previously_seen ? 'Yes' : 'No'}</li>
          <li>Times Seen: {item.historical_data.times_seen}</li>
          <li>First Seen: {item.historical_data.first_seen}</li>
          <li>Last Seen: {item.historical_data.last_seen}</li>
        </Typography>
      </Paper>
    ));
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
          <ListItem button>
            <ListItemIcon><Settings /></ListItemIcon>
            <ListItemText primary="Settings" />
          </ListItem>
        </List>
        <Divider />
        <Typography variant="body2" align="center" style={{ padding: '16px' }}>
          &copy; 2024 Analyzer Inc.
        </Typography>
      </Drawer>
      <Container className="container">
        {currentTab === 'scan' && (
          <>
            <Typography className="title" variant="h4" gutterBottom>
              Multi-media scanner CS2
            </Typography>
            <form onSubmit={handleSubmit} className="upload-form">
              <input type="file" onChange={handleFileChange} className="file-input" />
              {error && <Typography variant="body2" className="error-message">{error}</Typography>}
              <TextField
                label="Download URL"
                value={downloadUrl}
                onChange={handleUrlChange}
                fullWidth
                margin="normal"
                InputLabelProps={{
                  style: { color: '#000000' , font: 'bold'}
                }}
                InputProps={{
                  style: { color: '#000000' }
                }}
              />
              <Button type="submit" variant="contained" color="primary" disabled={isLoading || !file || !downloadUrl}>
                Upload and Scan
              </Button>
            </form>
            {isLoading && (
              <Box mt={2} display="flex" justifyContent="center">
                <CircularProgress />
                <Typography variant="body1" style={{ marginLeft: '10px', color: '#ffffff' }}>
                  Scanning...
                </Typography>
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

