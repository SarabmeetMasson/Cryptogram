import cv2
import numpy as np

# Prompt user to enter the video file name
filename = input("Enter the name of the video file (with extension): ")

# Prompt user to enter the message to hide
message = input("Enter the message to hide: ")

# Prompt user to enter the output file name and extension
output_filename = input("Enter the desired name of the output file (with extension): ")

# Load the video
cap = cv2.VideoCapture(filename)

# Get the number of frames in the video
frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

# Read the first frame
ret, frame = cap.read()

# Check if the frame was read successfully
if not ret:
    print("Error: Could not read video frame")
    exit()

# Get the height, width, and channels of the frame
height, width, channels = frame.shape

# Calculate the maximum message length that can be encoded in the video
max_message_length = ((height * width) // 16) - 2

# Check if the message is too long to be encoded in the video
if len(message) > max_message_length:
    print("Error: Message is too long to be encoded in the video")
    exit()

# Encode the message length into the blue channel of the first frame
binary_length = '{0:016b}'.format(len(message))
blue_channel = frame[:, :, 0]
for i in range(16):
    blue_channel[0, i] &= 254
    blue_channel[0, i] |= int(binary_length[i])

# Write the modified first frame to the output video
out = cv2.VideoWriter(output_filename, cv2.VideoWriter_fourcc(*'avc1'), 30, (width, height))
out.write(frame)

# Encode the message into the blue channel of the remaining frames
for i in range(1, frame_count):
    # Read the frame
    ret, frame = cap.read()

    # Check if the frame was read successfully
    if not ret:
        break

    # Encode the message into the blue channel of the frame
    if i <= len(message):
        char_code = ord(message[i-1])
        binary_code = '{0:08b}'.format(char_code)
        blue_channel = frame[:, :, 0]
        blue_channel[-1, -1] = int(binary_code[-1])
        blue_channel[-1, -2] = int(binary_code[-2])
        blue_channel[-2, -1] = int(binary_code[-3])
        blue_channel[-2, -2] = int(binary_code[-4])

    # Write the modified frame to the output video
    out.write(frame)

# Release the video capture and writer objects
cap.release()
out.release()

print("Message hidden successfully!")
