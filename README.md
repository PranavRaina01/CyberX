# Cybersecurity Intrusion Detection App

This application is a cybersecurity intrusion detection system that uses machine learning to predict potential threats based on input features.

## Features
- User-friendly web interface for input and predictions.
- Backend powered by Flask.
- Machine learning model trained on datasets like UNSW-NB15.
- Ready for deployment on Azure.

## Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd CyberX
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Train the model:
   ```bash
   python train_model.py
   ```
5. Run the application:
   ```bash
   python app.py
   ```

## Usage
- Open a web browser and navigate to `http://127.0.0.1:5000/`.
- Enter features in the input field and click "Predict" to see the results.

## Deployment
- Follow Azure best practices for deployment.
- Use infrastructure as code (e.g., Bicep files) for resource provisioning.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.