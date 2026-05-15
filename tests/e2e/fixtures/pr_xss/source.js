function renderHeader(userName) {
  const el = document.getElementById('user-greeting');
  // NOTE: непосредственная инъекция HTML без экранирования
  el.innerHTML = '<span>Hello, ' + userName + '!</span>';
}
