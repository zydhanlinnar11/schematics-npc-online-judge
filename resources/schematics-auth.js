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
    if (response.status != 200) throw new Error('Login failed')
    return { success: true }
  } catch (err) {
    throw err
  }
}
