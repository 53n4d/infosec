// frontend/src/intel.js
// All Firestore operations — called from components and api.js
import {
  doc,
  getDoc,
  setDoc,
  updateDoc,
  arrayUnion,
  increment,
  serverTimestamp,
  collection,
  Timestamp,
} from 'firebase/firestore'
import { db } from './firebase'

// ── Helpers ───────────────────────────────────────────────────────────────

function ageDays(ts) {
  if (!ts) return 9999
  const ms = ts?.toDate ? ts.toDate().getTime() : new Date(ts).getTime()
  return Math.floor((Date.now() - ms) / 86400000)
}

export function freshnessLabel(age) {
  if (age <  1) return 'fresh'
  if (age <  7) return 'recent'
  if (age < 30) return 'aging'
  return 'stale'
}

function rangeKey(country, rirs) {
  return `${country.toUpperCase()}_${[...rirs].sort().join('_')}`
}

function cveKey(software, version) {
  const base = (software + (version ? '__' + version : ''))
    .toLowerCase().replace(/[\s/]/g, '_')
  return base.slice(0, 200)
}

// ══════════════════════════════════════════════════════════════════════════
// Range cache  (30-day TTL)
// ══════════════════════════════════════════════════════════════════════════

export async function getCachedRanges(country, rirs) {
  try {
    const key  = rangeKey(country, rirs)
    const snap = await getDoc(doc(db, 'range_cache', key))
    if (!snap.exists()) return null
    const data = snap.data()
    const age  = ageDays(data.cached_at)
    if (age >= 30) return null   // stale — caller fetches fresh
    return { ...data, from_cache: true, age_days: age, freshness: freshnessLabel(age) }
  } catch (e) {
    console.warn('[intel] range cache read:', e.message)
    return null
  }
}

export async function saveCachedRanges(country, rirs, result) {
  try {
    const key = rangeKey(country, rirs)
    await setDoc(doc(db, 'range_cache', key), {
      country:      result.country,
      country_name: result.country_name || '',
      rirs:         result.rirs || rirs,
      counts:       result.counts || {},
      total:        result.total  || result.ranges?.length || 0,
      ranges:       result.ranges || [],
      last_updated: result.last_updated || null,
      masscan_hint: result.masscan_hint  || null,
      cached_at:    serverTimestamp(),
    })
  } catch (e) {
    console.warn('[intel] range cache write:', e.message)
  }
}

// ══════════════════════════════════════════════════════════════════════════
// CVE cache  (7-day TTL)
// ══════════════════════════════════════════════════════════════════════════

export async function getCachedCves(software, version) {
  try {
    const key  = cveKey(software, version)
    const snap = await getDoc(doc(db, 'cve_cache', key))
    if (!snap.exists()) return null
    const data = snap.data()
    if (ageDays(data.cached_at) >= 7) return null
    return data.cves || []
  } catch (e) {
    console.warn('[intel] CVE cache read:', e.message)
    return null
  }
}

export async function saveCachedCves(software, version, cves) {
  try {
    const key = cveKey(software, version)
    await setDoc(doc(db, 'cve_cache', key), {
      software,
      version:   version || null,
      cves,
      cached_at: serverTimestamp(),
    })
  } catch (e) {
    console.warn('[intel] CVE cache write:', e.message)
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Country intel  (crowdsourced scan results)
// ══════════════════════════════════════════════════════════════════════════

export async function getCountryIntel(country) {
  try {
    const snap = await getDoc(doc(db, 'country_intel', country.toUpperCase()))
    if (!snap.exists()) return { found: false, country: country.toUpperCase() }
    const data = snap.data()
    const age  = ageDays(data.last_scanned)
    return {
      ...data,
      found:     true,
      age_days:  age,
      freshness: freshnessLabel(age),
      stale:     age >= 30,
    }
  } catch (e) {
    console.warn('[intel] country intel read:', e.message)
    return { found: false, country: country.toUpperCase() }
  }
}

export async function contributeCountryIntel(country, payload) {
  try {
    const ref = doc(db, 'country_intel', country.toUpperCase())
    const snap = await getDoc(ref)

    const newHits = payload.hits || []

    // Merge hits — keep last 500
    const existingHits = snap.exists() ? (snap.data().hits || []) : []
    const mergedHits   = [...existingHits, ...newHits].slice(-500)

    // Top software frequency
    const swCount = {}
    for (const hit of mergedHits) {
      if (hit?.software) swCount[hit.software] = (swCount[hit.software] || 0) + 1
    }
    const topSoftware = Object.entries(swCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([sw]) => sw)

    // CVE summary — unique, sorted by score desc
    const cveMap = {}
    for (const hit of mergedHits) {
      for (const cve of hit?.cves || []) {
        if (cve?.id && !cveMap[cve.id]) cveMap[cve.id] = cve
      }
    }
    const cveSummary = Object.values(cveMap)
      .sort((a, b) => parseFloat(b.score || 0) - parseFloat(a.score || 0))
      .slice(0, 20)

    const data = {
      country:      country.toUpperCase(),
      country_name: payload.country_name || '',
      last_scanned: serverTimestamp(),
      scan_count:   increment(1),
      stats: {
        probed: payload.probed || 0,
        open:   payload.open   || 0,
        vulns:  payload.vulns  || 0,
      },
      hits:         mergedHits,
      top_software: topSoftware,
      cve_summary:  cveSummary,
      ranges:       payload.ranges || [],
    }

    await setDoc(ref, data, { merge: true })
    console.log('[intel] contributed:', country.toUpperCase())
  } catch (e) {
    console.warn('[intel] contribute failed:', e.message)
  }
}