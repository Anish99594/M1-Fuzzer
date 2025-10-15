# FastAPI SCALE Server

## Overview
This project implements a FastAPI server that utilizes the SCALE codec for serialization and deserialization of data. It includes custom Enum definitions to ensure compatibility with the SCALE types and provides robust error handling to enhance system resilience.

## Project Structure
```
fastapi-scale-server
├── src
│   ├── main.py                # Entry point of the FastAPI application
│   ├── api
│   │   └── endpoints.py       # API endpoints definition
│   ├── models
│   │   └── scale_enum.py      # Custom Enum class for SCALE types
│   ├── utils
│   │   └── scale_codec.py     # Utility functions for SCALE codec
│   └── types
│       └── custom_enum.py     # Additional custom types or Enums
├── requirements.txt           # Project dependencies
├── README.md                  # Project documentation
└── tests
    └── test_scale_codec.py    # Unit tests for SCALE codec utilities
```

## Setup Instructions
1. Clone the repository:
   ```
   git clone <repository-url>
   cd fastapi-scale-server
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the FastAPI server:
   ```
   uvicorn src.main:app --reload
   ```

## Usage
- The API endpoints can be accessed at `http://localhost:8000`.
- Use tools like Postman or curl to interact with the API.

## API Endpoints
- The available endpoints are defined in `src/api/endpoints.py`. Each endpoint utilizes the SCALE codec for data handling.

## Testing
- Unit tests for the SCALE codec utilities are located in `tests/test_scale_codec.py`.
- Run the tests using:
   ```
   pytest tests/test_scale_codec.py
   ```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License.