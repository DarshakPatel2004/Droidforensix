// /dissection/classes returns at most 200 classes per page. Load every page so
// search and counts cover the whole APK, not just the first page (audit F-01, F-02).
const PAGE_SIZE = 200

export async function fetchAllDissectionClasses(apiUrl, sampleId) {
  const classes = []
  let offset = 0
  let total
  do {
    const res = await fetch(
      `${apiUrl}/api/sample/${sampleId}/dissection/classes?offset=${offset}&limit=${PAGE_SIZE}`,
    )
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const page = await res.json()
    const pageClasses = page.classes || []
    classes.push(...pageClasses)
    total = page.total ?? classes.length
    if (pageClasses.length === 0) break
    offset += pageClasses.length
  } while (offset < total)
  return { classes, total }
}
