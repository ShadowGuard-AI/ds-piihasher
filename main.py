import argparse
import logging
import os
import json
import csv
import pandas as pd
import bcrypt
from faker import Faker
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Faker for synthetic data generation
fake = Faker()

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='ds-PIIHasher: Anonymize and pseudonymize sensitive data.')
    parser.add_argument('input_file', type=str, help='Path to the input file (CSV, JSON, or TXT).')
    parser.add_argument('output_file', type=str, help='Path to the output file.')
    parser.add_argument('--file_type', type=str, choices=['csv', 'json', 'txt'], help='Specify the file type explicitly (csv, json, txt).  If not specified, the script attempts to infer based on the file extension.')
    parser.add_argument('--fields', type=str, nargs='+', help='List of fields (columns) to anonymize (for CSV and JSON). If not specified, all fields will be checked.')
    parser.add_argument('--pii_types', type=str, nargs='+', default=['EMAIL_ADDRESS', 'PHONE_NUMBER', 'CREDIT_CARD', 'PERSON', 'IBAN_CODE', 'US_SSN'], help='List of PII types to detect (default: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, PERSON, IBAN_CODE, US_SSN).  See Presidio documentation for full list of supported types.')
    parser.add_argument('--hash', action='store_true', help='Enable reversible hashing of PII using bcrypt.')
    parser.add_argument('--replace', action='store_true', help='Enable PII replacement with synthetic data.')
    parser.add_argument('--seed', type=int, help='Optional seed for the Faker instance to generate consistent synthetic data across multiple runs.')


    return parser.parse_args()

def detect_pii(text, pii_types=None):
    """
    Detects PII entities in the given text using Presidio.

    Args:
        text (str): The input text to analyze.
        pii_types (list): A list of PII types to detect.

    Returns:
        list: A list of Presidio RecognitionResult objects representing the detected PII entities.  Returns an empty list if no PII is found or if there's an error during analysis.
    """

    analyzer = AnalyzerEngine()
    try:
        results = analyzer.analyze(text=text, entities=pii_types, language='en')
        return results
    except Exception as e:
        logging.error(f"Error during PII detection: {e}")
        return []

def hash_pii(text):
    """
    Hashes the given text using bcrypt.

    Args:
        text (str): The text to hash.

    Returns:
        str: The bcrypt hash of the text, or None if an error occurred.
    """
    try:
        text_bytes = text.encode('utf-8')
        hashed_bytes = bcrypt.hashpw(text_bytes, bcrypt.gensalt())
        return hashed_bytes.decode('utf-8')
    except Exception as e:
        logging.error(f"Error during hashing: {e}")
        return None

def replace_pii(pii_type):
    """
    Replaces PII with synthetic data using Faker.

    Args:
        pii_type (str): The type of PII to replace.

    Returns:
        str: Synthetic data corresponding to the PII type, or None if the type is not supported.
    """
    try:
        if pii_type == 'EMAIL_ADDRESS':
            return fake.email()
        elif pii_type == 'PHONE_NUMBER':
            return fake.phone_number()
        elif pii_type == 'CREDIT_CARD':
            return fake.credit_card_number()
        elif pii_type == 'PERSON':
            return fake.name()
        elif pii_type == 'IBAN_CODE':
            return fake.iban()
        elif pii_type == 'US_SSN':
            return fake.ssn()
        else:
            logging.warning(f"Unsupported PII type for replacement: {pii_type}")
            return None
    except Exception as e:
        logging.error(f"Error during PII replacement: {e}")
        return None


def anonymize_text(text, pii_types, hash_pii_flag, replace_pii_flag):
    """
    Anonymizes the given text by either hashing or replacing detected PII.

    Args:
        text (str): The input text to anonymize.
        pii_types (list): A list of PII types to detect.
        hash_pii_flag (bool):  Flag indicating whether to hash detected PII.
        replace_pii_flag (bool): Flag indicating whether to replace detected PII.

    Returns:
        str: The anonymized text.
    """
    results = detect_pii(text, pii_types)
    anonymized_text = text

    # Sort results by start offset in reverse order to avoid index issues during replacement
    results = sorted(results, key=lambda x: x.start, reverse=True)

    for res in results:
        if res.score >= 0.8: # Only process if confidence score is high
            start = res.start
            end = res.end
            pii_entity = text[start:end]
            pii_type = res.entity_type

            if hash_pii_flag:
                hashed_value = hash_pii(pii_entity)
                if hashed_value:
                    anonymized_text = anonymized_text[:start] + hashed_value + anonymized_text[end:]
                else:
                    logging.warning(f"Failed to hash PII entity: {pii_entity}")

            elif replace_pii_flag:
                synthetic_data = replace_pii(pii_type)
                if synthetic_data:
                    anonymized_text = anonymized_text[:start] + synthetic_data + anonymized_text[end:]
                else:
                    logging.warning(f"Failed to replace PII entity: {pii_entity} (type: {pii_type})")
            else:
                  logging.warning("Neither hashing nor replacement enabled for PII entity.")

    return anonymized_text


def process_csv(input_file, output_file, fields, pii_types, hash_pii_flag, replace_pii_flag):
    """
    Processes a CSV file, anonymizing the specified fields.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output CSV file.
        fields (list): List of column names to anonymize. If None, all columns are processed.
        pii_types (list): A list of PII types to detect.
        hash_pii_flag (bool): Flag indicating whether to hash detected PII.
        replace_pii_flag (bool): Flag indicating whether to replace detected PII.
    """
    try:
        df = pd.read_csv(input_file)
        if fields is None:
            fields = df.columns.tolist()

        for field in fields:
            if field in df.columns:
                df[field] = df[field].astype(str).apply(lambda x: anonymize_text(x, pii_types, hash_pii_flag, replace_pii_flag))
            else:
                logging.warning(f"Field '{field}' not found in CSV. Skipping.")

        df.to_csv(output_file, index=False)
        logging.info(f"Successfully processed CSV file. Output saved to: {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except pd.errors.EmptyDataError:
        logging.error(f"Input CSV file is empty: {input_file}")
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")


def process_json(input_file, output_file, fields, pii_types, hash_pii_flag, replace_pii_flag):
    """
    Processes a JSON file, anonymizing the specified fields.

    Args:
        input_file (str): Path to the input JSON file.
        output_file (str): Path to the output JSON file.
        fields (list): List of field names to anonymize. If None, all fields are processed.
        pii_types (list): A list of PII types to detect.
        hash_pii_flag (bool): Flag indicating whether to hash detected PII.
        replace_pii_flag (bool): Flag indicating whether to replace detected PII.
    """
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)

        def anonymize_recursively(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if fields is None or key in fields:
                        if isinstance(value, str):
                            obj[key] = anonymize_text(value, pii_types, hash_pii_flag, replace_pii_flag)
                        else:
                            anonymize_recursively(value)  # Recurse for nested objects/lists
            elif isinstance(obj, list):
                for item in obj:
                    anonymize_recursively(item)

        anonymize_recursively(data)

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)

        logging.info(f"Successfully processed JSON file. Output saved to: {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in file: {input_file}")
    except Exception as e:
        logging.error(f"Error processing JSON file: {e}")


def process_txt(input_file, output_file, pii_types, hash_pii_flag, replace_pii_flag):
    """
    Processes a TXT file, anonymizing the entire content.

    Args:
        input_file (str): Path to the input TXT file.
        output_file (str): Path to the output TXT file.
        pii_types (list): A list of PII types to detect.
        hash_pii_flag (bool): Flag indicating whether to hash detected PII.
        replace_pii_flag (bool): Flag indicating whether to replace detected PII.
    """
    try:
        with open(input_file, 'r') as f:
            text = f.read()

        anonymized_text = anonymize_text(text, pii_types, hash_pii_flag, replace_pii_flag)

        with open(output_file, 'w') as f:
            f.write(anonymized_text)

        logging.info(f"Successfully processed TXT file. Output saved to: {output_file}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except Exception as e:
        logging.error(f"Error processing TXT file: {e}")


def main():
    """
    Main function to execute the ds-PIIHasher tool.
    """
    args = setup_argparse()

    # Input validation
    if not os.path.exists(args.input_file):
        logging.error(f"Input file does not exist: {args.input_file}")
        return

    if args.hash and args.replace:
        logging.error("Both --hash and --replace cannot be enabled simultaneously.  Choose one.")
        return


    # Determine file type
    if args.file_type:
        file_type = args.file_type
    else:
        file_type = args.input_file.split('.')[-1].lower()  # Infer from extension

    if file_type not in ['csv', 'json', 'txt']:
        logging.error(f"Unsupported file type: {file_type}.  Please specify --file_type or use a valid file extension (csv, json, txt).")
        return

    # Process based on file type
    if file_type == 'csv':
        process_csv(args.input_file, args.output_file, args.fields, args.pii_types, args.hash, args.replace)
    elif file_type == 'json':
        process_json(args.input_file, args.output_file, args.fields, args.pii_types, args.hash, args.replace)
    elif file_type == 'txt':
        process_txt(args.input_file, args.output_file, args.pii_types, args.hash, args.replace)

if __name__ == "__main__":
    main()