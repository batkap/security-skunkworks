export const endpoint = "https://api.example.com";

export function callApi(token: string) {
  return fetch(endpoint, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
}

