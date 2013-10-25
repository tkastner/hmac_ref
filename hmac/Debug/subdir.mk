################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../hmac.c \
../hmac_diff.c \
../rfc_hmac.c \
../sha.c 

OBJS += \
./hmac.o \
./hmac_diff.o \
./rfc_hmac.o \
./sha.o 

C_DEPS += \
./hmac.d \
./hmac_diff.d \
./rfc_hmac.d \
./sha.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/include/openssl -I/home/thms/Devel/Eclipse/hmac -O0 -g3 -Wall -c -lcrypto -std=c99 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


