// parsers/index.js - Parser router
// Detects file format and routes to correct parser

import { parseCloudTrail } from './cloudtrailParser.js';
import { parseCsv } from './csvParser.js';
import { parsePlaintext } from './plaintextParser.js';

/**
 * Detects the format of the uploaded file
 * @param {string} filename
 * @param {string} rawText
 * @param {string} mimetype
 * @returns {string} - 'cloudtrail' | 'csv' | 'plaintext'
 */
function detectFormat(filename, rawText, mimetype) {
  const ext = filename.split('.').pop().toLowerCase();
  const preview = rawText.slice(0, 500).trim();

  // CSV by extension or mimetype
  if (ext === 'csv' || mimetype === 'text/csv') return 'csv';

  // JSON - could be CloudTrail or generic JSON
  if (ext === 'json' || mimetype === 'application/json') {
    try {
      const parsed = JSON.parse(preview.length < 500 ? rawText : preview + '"}]}');
      if (parsed.Records || parsed.records) return 'cloudtrail';
    } catch (e) {
      // Not valid JSON snippet, try full parse
    }
    try {
      const parsed = JSON.parse(rawText);
      if (parsed.Records || parsed.records) return 'cloudtrail';
      if (Array.isArray(parsed) && parsed[0]?.eventName) return 'cloudtrail';
    } catch (e) {
      return 'plaintext';
    }
    return 'cloudtrail'; // Default JSON to cloudtrail attempt
  }

  // Plaintext
  return 'plaintext';
}

/**
 * Main parse function - routes to correct parser
 * @param {Buffer} fileBuffer - uploaded file buffer
 * @param {string} filename - original filename
 * @param {string} mimetype - file mimetype
 * @returns {Object} - { events, confidence, format, meta }
 */
export function parseFile(fileBuffer, filename, mimetype) {
  const rawText = fileBuffer.toString('utf-8');
  const format = detectFormat(filename, rawText, mimetype);

  console.log(`Detected format: ${format} for file: ${filename}`);

  let result;

  switch (format) {
    case 'cloudtrail':
      result = parseCloudTrail(rawText);
      break;
    case 'csv':
      result = parseCsv(rawText);
      break;
    case 'plaintext':
    default:
      result = parsePlaintext(rawText);
      break;
  }

  return {
    ...result,
    format,
    filename,
  };
}