const PORTAL_JUNIOR_PATH = '/sch-npc/portal/junior'
const LOGIN_PATH = `${PORTAL_JUNIOR_PATH}/accounts/schematics/auth/login`

function getTokenFromSchematics() {
  return localStorage.getItem('token')
}

async function tryLoginWithJWT(token, csrftoken) {
  try {
    const formData = new FormData()
    formData.append('token', token)
    const response = await fetch(`${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        'X-CSRFToken': csrftoken,
      },
      body: formData,
      mode: 'same-origin',
    })
    const json = await response.json()
    if (json.message === 'User does not exist') {
      alert(
        'Akun anda belum terdaftar di portal Schematics NPC 2021.\nPastikan akun anda sudah terverifikasi dan mohon menunggu beberapa saat lagi untuk sinkronisasi data.\nTerima kasih.'
      )
      return
    }
    if (response.status != 200) throw new Error('Login failed')
    return { success: true }
  } catch (err) {
    throw err
  }
}
