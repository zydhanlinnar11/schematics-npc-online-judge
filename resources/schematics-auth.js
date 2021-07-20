const SCHEMATICS_URL = 'https://schematics.its.ac.id'
const JWT_API_PATH = '/'
const PORTAL_JUNIOR_PATH = '/sch-npc/portal/junior'
const LOGIN_PATH = `${PORTAL_JUNIOR_PATH}/accounts/schematics/auth/login`

async function getTokenFromSchematics() {
  try {
    const response = await fetch(`${SCHEMATICS_URL}${JWT_API_PATH}`)
    const token = await response.json()
    return token
  } catch (err) {
    throw err
  }
}

async function tryLoginWithJWT(token, csrftoken) {
  try {
    const formData = new FormData()
    formData.append('token', token)
    const response = await fetch(`${SCHEMATICS_URL}${LOGIN_PATH}`, {
      method: 'POST',
      headers: {
        'X-CSRFToken': csrftoken,
      },
      body: formData,
      mode: 'same-origin',
    })
    if (response.status != 200) throw new Error('Login failed')
    return { success: true }
  } catch (err) {
    throw err
  }
}
