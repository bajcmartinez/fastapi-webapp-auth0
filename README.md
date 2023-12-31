# FastAPI Demo Web App with Auth0

This application is a small demo on how to integrate Auth0 for authentication in a FastAPI web application.

## How to run the server

1. Clone this repository
    ```
    git clone https://github.com/bajcmartinez/fastapi-webapp-auth0.git && cd fastapi-webapp-auth0
    ```
2. Create a `.env` file from `.env.example` and populate the values from your Auth0 Application. Here is 
   ```
   cp .env.example .env
   ```

3. Create a virtual environment and install dependencies
   
   ```
   # Create a venv
   python3 -m venv venv 
   
   # Activate
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

4. Start the server

   ```
   uvicorn main:app --reload
   ```
   
5. Visit `http://localhost:8000`

----

Rewatch this live stream on FastAPI authentication with Auth0 and Jinja templates!

- On [twitch](https://www.twitch.tv/videos/1990681238)
- On [YouTube](https://www.youtube.com/watch?v=BMLaMdob3Cs)

Where to find us: 
• Jess' LinkedIn: http://linkedin.com/in/jessicatemporal/
• Juan's LinkedIn: https://www.linkedin.com/in/bajcmartinez/

Sign up for Auth0's developer newsletter here: https://a0.to/nl-signup/python