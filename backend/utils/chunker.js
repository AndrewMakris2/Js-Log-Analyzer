// chunker.js - Splits large arrays of normalized events into chunks
// This prevents hitting LLM token limits on large log files

/**
 * Splits an array of events into chunks of a given size
 * @param {Array} events - normalized event objects
 * @param {number} chunkSize - number of events per chunk (default 500)
 * @returns {Array[]} - array of chunks
 */
export function chunkEvents(events, chunkSize = 500) {
  if (!events || events.length === 0) return [];

  const chunks = [];
  for (let i = 0; i < events.length; i += chunkSize) {
    chunks.push(events.slice(i, i + chunkSize));
  }

  console.log(`Chunked ${events.length} events into ${chunks.length} chunks of max ${chunkSize}`);
  return chunks;
}

/**
 * Splits raw text into chunks by line count
 * Used for plaintext logs before parsing
 * @param {string} text - raw log text
 * @param {number} linesPerChunk - lines per chunk (default 1000)
 * @returns {string[]} - array of text chunks
 */
export function chunkText(text, linesPerChunk = 1000) {
  if (!text) return [];

  const lines = text.split('\n').filter(line => line.trim().length > 0);
  const chunks = [];

  for (let i = 0; i < lines.length; i += linesPerChunk) {
    chunks.push(lines.slice(i, i + linesPerChunk).join('\n'));
  }

  console.log(`Chunked ${lines.length} lines into ${chunks.length} text chunks`);
  return chunks;
}

/**
 * Summarizes multiple chunk results into one combined result
 * Used when we process chunks separately and need to merge
 * @param {Array} chunkResults - array of analysis results per chunk
 * @returns {Object} - merged result
 */
export function mergeChunkResults(chunkResults) {
  if (!chunkResults || chunkResults.length === 0) return {};
  if (chunkResults.length === 1) return chunkResults[0];

  // Merge all events from all chunks
  const merged = {
    events: [],
    anomalies: [],
    sequences: [],
  };

  for (const result of chunkResults) {
    if (result.events) merged.events.push(...result.events);
    if (result.anomalies) merged.anomalies.push(...result.anomalies);
    if (result.sequences) merged.sequences.push(...result.sequences);
  }

  return merged;
}