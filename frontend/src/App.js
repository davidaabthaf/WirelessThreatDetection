import React, { useState, useEffect } from 'react';
import { Upload, Shield, Activity, AlertTriangle, X, Play, Calendar, Download, Lock, Eye, Radio, GitBranch, LogOut, User, FileText, Database, Bell, Settings, Search, BarChart3, FileSearch } from 'lucide-react';
import Login from './Login';
import jsPDF from 'jspdf';
import 'jspdf-autotable';

const WirelessSecurityDashboard = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [packetData, setPacketData] = useState([]);
  const [currentTime, setCurrentTime] = useState(new Date());

  // Digital Clock Update
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Check authentication on component mount
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const username = localStorage.getItem('username');
    if (token && username) {
      setIsAuthenticated(true);
      setCurrentUser(username);
    }
  }, []);

  const handleLoginSuccess = (data) => {
    setIsAuthenticated(true);
    setCurrentUser(data.username);
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setCurrentUser(null);
    setUploadedFile(null);
    setAnalysisComplete(false);
    setAnalysisResults(null);
    setPacketData([]);
  };

  // ========== REAL MLP BACKEND CONNECTION ==========
  const runAnalysis = async () => {
    if (!uploadedFile) return;
    setAnalyzing(true);
    
    try {
      const token = localStorage.getItem('authToken');
      const formData = new FormData();
      formData.append('file', uploadedFile);
      
      console.log('[+] Sending file to backend MLP for analysis...');
      console.log('[+] File:', uploadedFile.name, `(${(uploadedFile.size / 1024 / 1024).toFixed(2)} MB)`);
      
      const response = await fetch('http://localhost:5000/api/upload-pcap', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }
      
      const data = await response.json();
      console.log('[+] Backend response received:', data);
      
      if (data.success && data.results) {
        const backendResults = data.results;
        
        // Extract data from backend MLP
        const packets = backendResults.packets || [];
        const mlpResults = backendResults.results || [];
        const summary = backendResults.summary || {};
        
        console.log(`[+] MLP analyzed ${mlpResults.length} feature windows`);
        console.log(`[+] Total packets: ${packets.length}`);
        
        // Format packets for packet details table
        const formattedPackets = packets.map((pkt, idx) => ({
          no: pkt.packet_id || idx + 1,
          time: pkt.timestamp ? pkt.timestamp.toFixed(6) : '0.000000',
          source: pkt.source_mac || 'Unknown',
          destination: pkt.dest_mac || 'Unknown',
          protocol: pkt.protocol || '802.11',
          length: pkt.packet_size || 0
        }));
        
        // Format MLP classifications (each result is a window of packets)
        const classifications = mlpResults.map(result => ({
          packetNo: result.packet_id,
          classification: result.classification,
          threatType: result.threat_type,
          confidence: result.confidence,
          description: result.threat_description
        }));
        
        // Count threat types (excluding NORMAL)
        const threatCounts = {};
        classifications.forEach(c => {
          if (c.classification !== 'NORMAL' && c.threatType !== 'NORMAL') {
            const threat = c.threatType;
            threatCounts[threat] = (threatCounts[threat] || 0) + 1;
          }
        });
        
        // Get top 4 threats for display
        const topThreats = Object.entries(threatCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 4)
          .map(([threat, count]) => ({
            name: threat,
            count: count,
            percentage: Math.min(100, ((count / mlpResults.length) * 100 * 2)).toFixed(0)
          }));
        
        // Build final results object for dashboard
        const analysisResults = {
          totalPackets: summary.total_packets || mlpResults.length,
          normal: summary.normal || 0,
          suspicious: summary.suspicious || 0,
          attack: summary.attack || 0,
          avgConfidence: summary.avg_confidence ? summary.avg_confidence.toFixed(1) : '0.0',
          classifications: classifications,
          threatCounts: threatCounts,
          topThreats: topThreats,
          mlpSummary: summary,
          threatDetails: summary.threat_details || []
        };
        
        console.log('[+] Analysis Results:', analysisResults);
        console.log('[+] Normal:', analysisResults.normal);
        console.log('[+] Suspicious:', analysisResults.suspicious);
        console.log('[+] Attack:', analysisResults.attack);
        console.log('[+] Threats detected:', Object.keys(threatCounts));
        
        setPacketData(formattedPackets);
        setAnalysisResults(analysisResults);
        setAnalysisComplete(true);
        
        // Success notification
        alert(`✅ MLP Analysis Complete!\n\n` +
              `Model: 13-Threat Neural Network\n` +
              `Total Packets: ${analysisResults.totalPackets}\n` +
              `Normal: ${analysisResults.normal}\n` +
              `Suspicious: ${analysisResults.suspicious}\n` +
              `Attacks: ${analysisResults.attack}\n` +
              `Avg Confidence: ${analysisResults.avgConfidence}%\n` +
              `Unique Threats: ${Object.keys(threatCounts).length}`);
        
      } else {
        throw new Error(data.message || 'Analysis failed - no results returned');
      }
      
    } catch (error) {
      console.error('[-] Analysis error:', error);
      
      let errorMessage = `❌ MLP Analysis Failed!\n\n${error.message}\n\n`;
      errorMessage += `Troubleshooting:\n`;
      errorMessage += `1. Backend running? Check: python api_server.py\n`;
      errorMessage += `2. File format: Must be .pcap or .pcapng\n`;
      errorMessage += `3. File size: Must be < 100MB\n`;
      errorMessage += `4. Check backend terminal for detailed errors\n`;
      errorMessage += `5. Check browser console (F12) for more info`;
      
      alert(errorMessage);
      
    } finally {
      setAnalyzing(false);
    }
  };

  // PDF REPORT GENERATION
  const generatePDFReport = () => {
    if (!analysisResults || !packetData) {
      alert('No analysis data available for report generation');
      return;
    }

    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();

    // Header
    doc.setFillColor(0, 139, 139);
    doc.rect(0, 0, 210, 40, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.setFont(undefined, 'bold');
    doc.text('WIRELESS SECURITY ANALYSIS REPORT', 105, 20, { align: 'center' });
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');
    doc.text('MLP Neural Network - 13 Threat Detection', 105, 30, { align: 'center' });

    // Report Info
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.text(`Generated: ${timestamp}`, 14, 50);
    doc.text(`Analyst: ${currentUser}`, 14, 56);
    doc.text(`File: ${uploadedFile?.name || 'N/A'}`, 14, 62);

    // Executive Summary Box
    doc.setDrawColor(0, 139, 139);
    doc.setLineWidth(0.5);
    doc.rect(14, 70, 182, 45);
    doc.setFontSize(14);
    doc.setFont(undefined, 'bold');
    doc.text('EXECUTIVE SUMMARY', 105, 78, { align: 'center' });
    
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');
    doc.text(`Total Packets Analyzed: ${analysisResults.totalPackets}`, 20, 88);
    doc.text(`Average Confidence: ${analysisResults.avgConfidence}%`, 20, 95);
    doc.text(`Threat Types Detected: ${Object.keys(analysisResults.threatCounts).length}`, 20, 102);
    
    // Threat Level
    const threatLevel = analysisResults.attack > 10 ? 'HIGH' : analysisResults.attack > 5 ? 'MEDIUM' : 'LOW';
    const threatColor = threatLevel === 'HIGH' ? [239, 68, 68] : threatLevel === 'MEDIUM' ? [251, 191, 36] : [34, 197, 94];
    doc.setTextColor(...threatColor);
    doc.setFont(undefined, 'bold');
    doc.text(`Threat Level: ${threatLevel}`, 20, 109);
    doc.setTextColor(0, 0, 0);
    doc.setFont(undefined, 'normal');

    // Classification Results
    doc.setFontSize(14);
    doc.setFont(undefined, 'bold');
    doc.text('MLP CLASSIFICATION RESULTS', 14, 130);
    
    doc.autoTable({
      startY: 135,
      head: [['Category', 'Count', 'Percentage']],
      body: [
        ['Normal Traffic', analysisResults.normal, `${((analysisResults.normal / analysisResults.totalPackets) * 100).toFixed(1)}%`],
        ['Suspicious Activity', analysisResults.suspicious, `${((analysisResults.suspicious / analysisResults.totalPackets) * 100).toFixed(1)}%`],
        ['Attack Traffic', analysisResults.attack, `${((analysisResults.attack / analysisResults.totalPackets) * 100).toFixed(1)}%`],
      ],
      theme: 'grid',
      headStyles: { fillColor: [0, 139, 139], textColor: 255 },
      styles: { fontSize: 10 },
    });

    // Top Threats
    if (analysisResults.topThreats && analysisResults.topThreats.length > 0) {
      doc.setFontSize(14);
      doc.setFont(undefined, 'bold');
      doc.text('TOP THREATS DETECTED (MLP)', 14, doc.lastAutoTable.finalY + 15);
      
      const threatTableData = analysisResults.topThreats.map(threat => [
        threat.name,
        threat.count.toString(),
        `${threat.percentage}%`
      ]);

      doc.autoTable({
        startY: doc.lastAutoTable.finalY + 20,
        head: [['Threat Type', 'Occurrences', 'Severity']],
        body: threatTableData,
        theme: 'striped',
        headStyles: { fillColor: [239, 68, 68], textColor: 255 },
        styles: { fontSize: 10 },
      });
    }

    // Packet Details
    doc.addPage();
    doc.setFontSize(14);
    doc.setFont(undefined, 'bold');
    doc.text('DETAILED PACKET ANALYSIS', 14, 20);
    
    const packetTableData = packetData.slice(0, 20).map((packet, idx) => {
      const classification = analysisResults.classifications[idx];
      return [
        packet.no.toString(),
        packet.protocol,
        packet.source,
        packet.destination,
        classification?.classification || 'N/A',
        `${classification?.confidence || 0}%`
      ];
    });

    doc.autoTable({
      startY: 25,
      head: [['No', 'Protocol', 'Source', 'Destination', 'Type', 'Conf%']],
      body: packetTableData,
      theme: 'grid',
      headStyles: { fillColor: [0, 139, 139], textColor: 255, fontSize: 8 },
      styles: { fontSize: 7 },
      columnStyles: {
        0: { cellWidth: 15 },
        1: { cellWidth: 25 },
        2: { cellWidth: 45 },
        3: { cellWidth: 45 },
        4: { cellWidth: 30 },
        5: { cellWidth: 20 }
      }
    });

    // Footer
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(128, 128, 128);
      doc.text(`Page ${i} of ${pageCount}`, 105, 290, { align: 'center' });
      doc.text('CONFIDENTIAL - MLP Neural Network Analysis', 105, 285, { align: 'center' });
    }

    const filename = `MLP_Wireless_Report_${new Date().getTime()}.pdf`;
    doc.save(filename);
  };

  // CSV EXPORT GENERATION
  const generateCSVExport = () => {
    if (!analysisResults || !packetData) {
      alert('No analysis data available for CSV export');
      return;
    }

    let csvContent = 'Wireless Security Analysis - MLP Neural Network Export\n';
    csvContent += `Generated: ${new Date().toLocaleString()}\n`;
    csvContent += `Analyst: ${currentUser}\n`;
    csvContent += `File: ${uploadedFile?.name || 'N/A'}\n`;
    csvContent += `Model: 13-Threat MLP Classifier\n\n`;

    csvContent += 'SUMMARY STATISTICS\n';
    csvContent += 'Metric,Value\n';
    csvContent += `Total Packets,${analysisResults.totalPackets}\n`;
    csvContent += `Normal Traffic,${analysisResults.normal}\n`;
    csvContent += `Suspicious Activity,${analysisResults.suspicious}\n`;
    csvContent += `Attack Traffic,${analysisResults.attack}\n`;
    csvContent += `Average Confidence,${analysisResults.avgConfidence}%\n`;
    csvContent += `Threat Types,${Object.keys(analysisResults.threatCounts).length}\n\n`;

    if (analysisResults.topThreats && analysisResults.topThreats.length > 0) {
      csvContent += 'TOP THREATS (MLP DETECTED)\n';
      csvContent += 'Threat Type,Count,Percentage\n';
      analysisResults.topThreats.forEach(threat => {
        csvContent += `${threat.name},${threat.count},${threat.percentage}%\n`;
      });
      csvContent += '\n';
    }

    csvContent += 'MLP CLASSIFICATION DETAILS\n';
    csvContent += 'Window ID,Classification,Threat Type,Confidence,Description\n';
    analysisResults.classifications.forEach(c => {
      csvContent += `${c.packetNo},${c.classification},${c.threatType},${c.confidence}%,"${c.description || ''}"\n`;
    });
    csvContent += '\n';

    csvContent += 'PACKET DETAILS\n';
    csvContent += 'Packet No,Time,Source MAC,Destination MAC,Protocol,Length\n';
    
    packetData.forEach((packet) => {
      csvContent += `${packet.no},${packet.time},${packet.source},${packet.destination},${packet.protocol},${packet.length}\n`;
    });

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `MLP_Analysis_${new Date().getTime()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Updated useful features (placeholders for now)
  const usefulFeatures = [
    { name: 'Live Monitor', icon: Activity, active: true },
    { name: 'Threat Intel', icon: Shield, active: false },
    { name: 'Search Packets', icon: Search, active: false },
    { name: 'Analytics', icon: BarChart3, active: false },
    { name: 'Deep Scan', icon: FileSearch, active: false },
    { name: 'Alerts', icon: Bell, active: false },
    { name: 'Settings', icon: Settings, active: false }
  ];

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setUploadedFile(file);
      setAnalysisComplete(false);
    }
  };

  const removeFile = () => {
    setUploadedFile(null);
    setAnalysisComplete(false);
    setAnalysisResults(null);
    setPacketData([]);
  };

  const getDaysInMonth = () => {
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth();
    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const days = [];
    for (let i = 0; i < firstDay; i++) days.push(null);
    for (let i = 1; i <= daysInMonth; i++) days.push(i);
    return days;
  };

  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-black text-gray-100 relative overflow-hidden">
      <div className="absolute inset-0 opacity-10">
        <svg className="w-full h-full">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="cyan" strokeWidth="0.5"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>
      </div>

      {/* HEADER WITH DIGITAL CLOCK */}
      <div className="relative border-b border-cyan-500/30 bg-black/80 backdrop-blur-sm">
        <div className="max-w-full px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-10 h-10 text-cyan-400" />
              <div>
                <h1 className="text-3xl font-bold text-cyan-400 tracking-wider">ADVANCED WIRELESS SOC COMMAND CENTER</h1>
                <p className="text-xs text-cyan-300">MLP Neural Network - 13 Threat Detection System</p>
              </div>
            </div>
            
            {/* DIGITAL CLOCK */}
            <div className="flex items-center gap-4">
              <div className="bg-slate-900/70 border border-cyan-500/50 rounded-lg px-6 py-3 backdrop-blur-sm">
                <div className="text-center">
                  <div className="text-2xl font-bold text-cyan-400 tracking-wider font-mono">
                    {currentTime.toLocaleTimeString('en-US', { hour12: false })}
                  </div>
                  <div className="text-xs text-cyan-300 mt-1">
                    {currentTime.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-2 bg-slate-900/50 border border-cyan-500/30 rounded-lg px-4 py-2">
                <User className="w-5 h-5 text-cyan-400" />
                <span className="text-sm text-cyan-300 font-semibold">{currentUser}</span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-2 bg-red-900/30 hover:bg-red-900/50 border border-red-500/50 rounded-lg px-4 py-2 transition-colors"
              >
                <LogOut className="w-5 h-5 text-red-400" />
                <span className="text-sm text-red-300 font-semibold">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* USEFUL FEATURES BAR */}
      <div className="relative border-b border-cyan-500/20 bg-black/60 backdrop-blur-sm">
        <div className="max-w-full px-6 py-3">
          <div className="flex items-center justify-around">
            {usefulFeatures.map((feature, idx) => (
              <button
                key={idx}
                className={`flex flex-col items-center transition-all hover:scale-110 ${
                  feature.active 
                    ? 'opacity-100' 
                    : 'opacity-60 hover:opacity-100'
                }`}
              >
                <div className={`w-12 h-12 rounded-full ${
                  feature.active 
                    ? 'bg-cyan-500/30 border-2 border-cyan-400' 
                    : 'bg-cyan-900/30 border border-cyan-500/50'
                } flex items-center justify-center mb-1`}>
                  <feature.icon className={`w-6 h-6 ${
                    feature.active ? 'text-cyan-300' : 'text-cyan-400'
                  }`} />
                </div>
                <span className={`text-xs ${
                  feature.active ? 'text-cyan-300 font-semibold' : 'text-gray-400'
                }`}>
                  {feature.name}
                </span>
                {feature.active && (
                  <div className="w-1 h-1 bg-cyan-400 rounded-full mt-1"></div>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="relative grid grid-cols-12 gap-4 p-4">
        {/* LEFT COLUMN */}
        <div className="col-span-3 space-y-4">
          {/* Upload Section */}
          <div className="bg-gradient-to-br from-purple-900/20 to-indigo-900/20 border border-purple-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3 border-b border-purple-500/30 pb-2">
              <Upload className="w-5 h-5 text-purple-400" />
              <h3 className="text-sm font-bold text-white">Upload PCAP Evidence</h3>
            </div>
            {!uploadedFile ? (
              <label className="border-2 border-dashed border-purple-500/50 rounded-lg p-8 cursor-pointer hover:border-purple-500 transition-all block">
                <div className="text-center">
                  <Upload className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                  <p className="text-sm text-purple-200">Drop PCAP Here</p>
                  <p className="text-xs text-gray-500">Max 100MB</p>
                </div>
                <input type="file" accept=".pcap,.pcapng" onChange={handleFileUpload} className="hidden" />
              </label>
            ) : (
              <div className="space-y-2">
                <div className="bg-purple-900/30 border border-purple-500/40 rounded p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-white truncate">{uploadedFile.name}</p>
                      <p className="text-xs text-gray-400">{(uploadedFile.size / 1024 / 1024).toFixed(2)} MB</p>
                    </div>
                    <button onClick={removeFile} className="ml-2 p-1 hover:bg-red-500/20 rounded transition-colors">
                      <X className="w-4 h-4 text-red-400" />
                    </button>
                  </div>
                </div>
                <button onClick={runAnalysis} disabled={analyzing} className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white py-3 rounded-lg font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2">
                  {analyzing ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      MLP Analyzing...
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5" />
                      RUN MLP ANALYSIS
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {/* REPORT GENERATION */}
          {analysisResults && (
            <div className="bg-gradient-to-br from-green-900/20 to-emerald-900/20 border border-green-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3 border-b border-green-500/30 pb-2">
                <FileText className="w-5 h-5 text-green-400" />
                <h3 className="text-sm font-bold text-white">Generate Reports</h3>
              </div>
              <div className="space-y-2">
                <button
                  onClick={generatePDFReport}
                  className="w-full bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-500 hover:to-pink-500 text-white py-3 rounded-lg font-bold transition-all flex items-center justify-center gap-2"
                >
                  <FileText className="w-5 h-5" />
                  PDF REPORT
                </button>
                <button
                  onClick={generateCSVExport}
                  className="w-full bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white py-3 rounded-lg font-bold transition-all flex items-center justify-center gap-2"
                >
                  <Download className="w-5 h-5" />
                  CSV EXPORT
                </button>
              </div>
              <div className="mt-3 pt-3 border-t border-green-500/20">
                <p className="text-xs text-gray-400 text-center">
                  MLP Neural Network Results
                </p>
              </div>
            </div>
          )}

          {/* Packet Event Log */}
          <div className="bg-gradient-to-br from-blue-900/20 to-indigo-900/20 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3 border-b border-blue-500/30 pb-2">
              <Activity className="w-5 h-5 text-blue-400" />
              <h3 className="text-sm font-bold text-white">MLP Analysis Summary</h3>
            </div>
            {analysisResults ? (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-blue-300 mb-2">Classification Results</div>
                <div className="bg-green-900/20 border border-green-500/40 rounded p-2 flex items-center justify-between">
                  <span className="text-xs text-gray-300">Normal:</span>
                  <span className="text-lg font-bold text-green-400">{analysisResults.normal}</span>
                </div>
                <div className="bg-yellow-900/20 border border-yellow-500/40 rounded p-2 flex items-center justify-between">
                  <span className="text-xs text-gray-300">Suspicious:</span>
                  <span className="text-lg font-bold text-yellow-400">{analysisResults.suspicious}</span>
                </div>
                <div className="bg-red-900/20 border border-red-500/40 rounded p-2 flex items-center justify-between">
                  <span className="text-xs text-gray-300">Attacks:</span>
                  <span className="text-lg font-bold text-red-400">{analysisResults.attack}</span>
                </div>
                <div className="mt-3 pt-3 border-t border-blue-500/20">
                  <div className="text-xs font-semibold text-blue-300 mb-2">Top Detections</div>
                  <div className="bg-slate-900/60 rounded border border-blue-500/20 max-h-64 overflow-y-auto">
                    <table className="w-full text-xs">
                      <thead className="sticky top-0 bg-slate-900">
                        <tr className="border-b border-blue-500/20">
                          <th className="text-left p-2 text-blue-300">Window</th>
                          <th className="text-left p-2 text-blue-300">Type</th>
                          <th className="text-right p-2 text-blue-300">Conf%</th>
                        </tr>
                      </thead>
                      <tbody>
                        {analysisResults.classifications.slice(0, 10).map((c, idx) => (
                          <tr key={idx} className="border-b border-slate-800 hover:bg-blue-900/10">
                            <td className="p-2 text-gray-400">#{c.packetNo}</td>
                            <td className="p-2">
                              <span className={`text-xs font-bold ${c.classification === 'NORMAL' ? 'text-green-400' : c.classification === 'SUSPICIOUS' ? 'text-yellow-400' : 'text-red-400'}`}>
                                {c.classification}
                              </span>
                            </td>
                            <td className="p-2 text-right text-cyan-400">{c.confidence}%</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Activity className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p className="text-xs">No MLP analysis yet</p>
              </div>
            )}
          </div>
        </div>

        {/* MIDDLE COLUMN */}
        <div className="col-span-6 space-y-4">
          {/* Activities */}
          <div className="bg-gradient-to-br from-slate-900/40 to-slate-800/40 border border-cyan-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3 border-b border-cyan-500/30 pb-2">
              <Calendar className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">THREAT ANALYSIS</h3>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-center mb-2">
                  <div className="flex items-center justify-between px-2">
                    <button className="text-cyan-400 hover:text-cyan-300">◀</button>
                    <span className="text-sm font-bold text-cyan-400">January</span>
                    <button className="text-cyan-400 hover:text-cyan-300">▶</button>
                  </div>
                </div>
                <div className="grid grid-cols-7 gap-1 text-xs">
                  {['S', 'M', 'T', 'W', 'T', 'F', 'S'].map((d, i) => (
                    <div key={i} className="text-center text-gray-500 font-semibold">{d}</div>
                  ))}
                  {getDaysInMonth().map((day, i) => (
                    <div key={i} className={`text-center p-1 ${day ? 'text-gray-300 hover:bg-cyan-500/20 cursor-pointer rounded' : ''} ${day === 13 ? 'bg-cyan-500 text-white rounded font-bold' : ''}`}>
                      {day || ''}
                    </div>
                  ))}
                </div>
              </div>
              <div className="col-span-2">
                {analysisResults && analysisResults.topThreats.length > 0 ? (
                  <div className="grid grid-cols-4 gap-3">
                    {analysisResults.topThreats.map((threat, idx) => (
                      <div key={idx} className="text-center">
                        <svg className="w-20 h-20 mx-auto" viewBox="0 0 100 100">
                          <circle cx="50" cy="50" r="35" fill="none" stroke="#1e293b" strokeWidth="10" />
                          <circle cx="50" cy="50" r="35" fill="none" stroke={idx === 0 ? '#ef4444' : idx === 1 ? '#f59e0b' : idx === 2 ? '#06b6d4' : '#8b5cf6'} strokeWidth="10" strokeDasharray={`${(threat.percentage / 100) * 220} 220`} strokeDashoffset="0" transform="rotate(-90 50 50)" />
                          <text x="50" y="50" textAnchor="middle" dy="7" className="text-sm font-bold fill-white">{threat.percentage}%</text>
                        </svg>
                        <div className="text-xs text-gray-400 mt-1 truncate px-1">{threat.name}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500 text-sm">Upload PCAP for MLP analysis</div>
                )}
              </div>
            </div>
            {analysisResults && (
              <div className="mt-4 pt-4 border-t border-cyan-500/20">
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="bg-slate-800/50 rounded p-2">
                    <div className="text-gray-400">Total Windows</div>
                    <div className="text-cyan-400 font-bold text-lg">{analysisResults.totalPackets}</div>
                  </div>
                  <div className="bg-slate-800/50 rounded p-2">
                    <div className="text-gray-400">MLP Confidence</div>
                    <div className="text-green-400 font-bold text-lg">{analysisResults.avgConfidence}%</div>
                  </div>
                  <div className="bg-slate-800/50 rounded p-2">
                    <div className="text-gray-400">Threats Found</div>
                    <div className="text-red-400 font-bold text-lg">{Object.keys(analysisResults.threatCounts).length}</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Alert Classification Graph */}
          <div className="bg-gradient-to-br from-blue-900/20 to-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3 border-b border-cyan-500/30 pb-2">
              <div className="flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">MLP Confidence Graph</h3>
              </div>
              <div className="flex gap-3 text-xs">
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-gray-400">Normal</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                  <span className="text-gray-400">Suspicious</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  <span className="text-gray-400">Attack</span>
                </div>
              </div>
            </div>
            {analysisResults ? (
              <div className="relative">
                <div className="relative h-56 bg-slate-900/30 rounded p-4">
                  <div className="absolute left-0 top-0 bottom-0 w-8 flex flex-col justify-between text-xs text-cyan-400 py-4">
                    <span>100%</span>
                    <span>75%</span>
                    <span>50%</span>
                    <span>25%</span>
                    <span>0%</span>
                  </div>
                  
                  <div className="ml-8 mr-4 h-full relative">
                    <svg className="w-full h-full" viewBox="0 0 400 200">
                      <defs>
                        <pattern id="graphGrid" width="40" height="40" patternUnits="userSpaceOnUse">
                          <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5"/>
                        </pattern>
                      </defs>
                      <rect width="100%" height="100%" fill="url(#graphGrid)" opacity="0.3" />
                      
                      <line x1="0" y1="0" x2="400" y2="0" stroke="#06b6d4" strokeWidth="0.5" opacity="0.3" />
                      <line x1="0" y1="50" x2="400" y2="50" stroke="#06b6d4" strokeWidth="0.5" opacity="0.3" />
                      <line x1="0" y1="100" x2="400" y2="100" stroke="#06b6d4" strokeWidth="0.5" opacity="0.3" />
                      <line x1="0" y1="150" x2="400" y2="150" stroke="#06b6d4" strokeWidth="0.5" opacity="0.3" />
                      <line x1="0" y1="200" x2="400" y2="200" stroke="#06b6d4" strokeWidth="0.5" opacity="0.3" />
                      
                      {analysisResults.classifications.slice(0, 40).map((c, idx) => {
                        const x = (idx / 39) * 380 + 10;
                        const y = 200 - (parseFloat(c.confidence) / 100) * 180 - 10;
                        const color = c.classification === 'NORMAL' ? '#22c55e' : c.classification === 'SUSPICIOUS' ? '#eab308' : '#ef4444';
                        const prevIdx = idx - 1;
                        
                        return (
                          <g key={idx}>
                            {idx > 0 && (
                              <line 
                                x1={(prevIdx / 39) * 380 + 10}
                                y1={200 - (parseFloat(analysisResults.classifications[prevIdx].confidence) / 100) * 180 - 10}
                                x2={x}
                                y2={y}
                                stroke={color}
                                strokeWidth="2"
                                opacity="0.6"
                              />
                            )}
                            
                            <circle 
                              cx={x}
                              cy={y}
                              r="3"
                              fill={color}
                              stroke={color}
                              strokeWidth="1"
                            >
                              <title>Window #{c.packetNo}: {c.classification} - {c.confidence}%</title>
                            </circle>
                            
                            {idx % 10 === 0 && (
                              <text
                                x={x}
                                y={y - 8}
                                textAnchor="middle"
                                fontSize="8"
                                fill="#06b6d4"
                                fontWeight="bold"
                              >
                                {c.confidence}%
                              </text>
                            )}
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                  
                  <div className="ml-8 mr-4 flex justify-between text-xs text-cyan-400 mt-2">
                    <span>Win #1</span>
                    <span>Win #10</span>
                    <span>Win #20</span>
                    <span>Win #30</span>
                    <span>Win #40</span>
                  </div>
                </div>
                
                <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                  <div className="bg-slate-900/50 rounded p-2 text-center">
                    <div className="text-gray-400">Avg Confidence</div>
                    <div className="text-cyan-400 font-bold text-lg">{analysisResults.avgConfidence}%</div>
                  </div>
                  <div className="bg-slate-900/50 rounded p-2 text-center">
                    <div className="text-gray-400">Windows</div>
                    <div className="text-cyan-400 font-bold text-lg">{Math.min(40, analysisResults.classifications.length)}</div>
                  </div>
                  <div className="bg-slate-900/50 rounded p-2 text-center">
                    <div className="text-gray-400">Attack Rate</div>
                    <div className="text-red-400 font-bold text-lg">
                      {analysisResults.totalPackets > 0 ? ((analysisResults.attack / analysisResults.totalPackets) * 100).toFixed(1) : '0.0'}%
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-56 flex items-center justify-center text-gray-500 text-sm">Run MLP analysis to see graph</div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="col-span-3 space-y-4">
          {/* AI Threat Classification */}
          <div className="bg-gradient-to-br from-red-900/20 to-orange-900/20 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3 border-b border-red-500/30 pb-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <h3 className="text-sm font-bold text-white">MLP Threat Detection</h3>
              </div>
              <div className="flex gap-1">
                <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse" />
                <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }} />
                <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }} />
              </div>
            </div>
            {analysisResults ? (
              <>
                <div className="flex justify-center mb-4">
                  <div className="relative w-36 h-36">
                    <svg viewBox="0 0 100 100" className="transform -rotate-90">
                      <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="15" />
                      <circle cx="50" cy="50" r="40" fill="none" stroke="#22c55e" strokeWidth="15" strokeDasharray={`${(analysisResults.normal / analysisResults.totalPackets) * 251.2} 251.2`} />
                      <circle cx="50" cy="50" r="40" fill="none" stroke="#eab308" strokeWidth="15" strokeDasharray={`${(analysisResults.suspicious / analysisResults.totalPackets) * 251.2} 251.2`} strokeDashoffset={`-${(analysisResults.normal / analysisResults.totalPackets) * 251.2}`} />
                      <circle cx="50" cy="50" r="40" fill="none" stroke="#ef4444" strokeWidth="15" strokeDasharray={`${(analysisResults.attack / analysisResults.totalPackets) * 251.2} 251.2`} strokeDashoffset={`-${((analysisResults.normal + analysisResults.suspicious) / analysisResults.totalPackets) * 251.2}`} />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-xl font-bold text-white">{analysisResults.totalPackets}</div>
                        <div className="text-xs text-gray-400">Total</div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="space-y-2 mb-4 text-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      <span className="text-gray-300">Normal</span>
                    </div>
                    <span className="text-white font-bold">{analysisResults.normal}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                      <span className="text-gray-300">Suspicious</span>
                    </div>
                    <span className="text-white font-bold">{analysisResults.suspicious}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <span className="text-gray-300">Attack</span>
                    </div>
                    <span className="text-white font-bold">{analysisResults.attack}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between bg-slate-900/50 border border-cyan-500/30 rounded p-3">
                  <span className="text-sm text-cyan-400 font-semibold">MLP Accuracy: {analysisResults.avgConfidence}%</span>
                  <div className="bg-red-500/30 border border-red-500 rounded px-2 py-1 text-xs font-bold text-red-400">
                    Threats: {Object.keys(analysisResults.threatCounts).length}
                  </div>
                </div>
              </>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-gray-500">
                <AlertTriangle className="w-16 h-16 mb-3 opacity-20" />
                <p className="text-sm">Awaiting MLP analysis</p>
              </div>
            )}
          </div>

          {/* Packet Details */}
          {packetData.length > 0 && (
            <div className="bg-gradient-to-br from-slate-900/40 to-slate-800/40 border border-cyan-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3 border-b border-cyan-500/30 pb-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Packet Details</h3>
              </div>
              <div className="bg-slate-900/60 rounded border border-cyan-500/20 max-h-96 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-slate-900">
                    <tr className="border-b border-cyan-500/20">
                      <th className="text-left p-2 text-cyan-300">No</th>
                      <th className="text-left p-2 text-cyan-300">Time</th>
                      <th className="text-left p-2 text-cyan-300">Source</th>
                      <th className="text-left p-2 text-cyan-300">Dest</th>
                      <th className="text-left p-2 text-cyan-300">Protocol</th>
                      <th className="text-right p-2 text-cyan-300">Length</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packetData.slice(0, 15).map((packet, idx) => (
                      <tr key={idx} className="border-b border-slate-800 hover:bg-cyan-900/10">
                        <td className="p-2 text-gray-400">{packet.no}</td>
                        <td className="p-2 text-gray-400">{packet.time}</td>
                        <td className="p-2 text-cyan-400 font-mono text-xs">{packet.source}</td>
                        <td className="p-2 text-purple-400 font-mono text-xs">{packet.destination}</td>
                        <td className="p-2 text-green-400">{packet.protocol}</td>
                        <td className="p-2 text-right text-gray-400">{packet.length}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default WirelessSecurityDashboard;