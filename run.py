from app import create_app

app = create_app()

if __name__ == "__main__":
    # host="0.0.0.0" so physical devices on the LAN can reach the server (not
    # just localhost). Port 8000 avoids the macOS AirPlay Receiver, which holds
    # port 5000.
    app.run(host="0.0.0.0", port=8000, debug=True, ssl_context="adhoc")