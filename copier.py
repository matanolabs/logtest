# Written by ChatGPT :)

import os
import uuid
import boto3
import argparse

# Set up the argument parser
parser = argparse.ArgumentParser(description='Copy .log files from a source directory to an S3 bucket with a unique ID in the destination path')
parser.add_argument('src_dir', help='the source directory')
parser.add_argument('dst_bucket', help='the destination S3 bucket')
parser.add_argument('dst_prefix', help='the destination prefix in the S3 bucket')
args = parser.parse_args()

# Set up the S3 client
s3 = boto3.client('s3')

# Walk through the source directory and copy each .log file to S3
for root, dirs, files in os.walk(args.src_dir):
    for file in files:
        if file.endswith('.log'):
            # Generate a unique ID to use in the destination path
            unique_id = str(uuid.uuid4())
            dst_path = f'{args.dst_prefix}/{unique_id}/{file}'

            # Print the fully qualified source and destination paths
            src_path = os.path.join(root, file)
            dst_url = f's3://{args.dst_bucket}/{dst_path}'
            print(f'\n📂 Copying {src_path} 🚀 to {dst_url}')

            # Copy the file to S3
            s3.upload_file(src_path, args.dst_bucket, dst_path)

print('\n🎉 All files copied successfully! 🎉')
