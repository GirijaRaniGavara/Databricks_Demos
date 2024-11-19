# Databricks notebook source
# MAGIC %md
# MAGIC ## GDPR implementation using the 
# MAGIC ## Pseudonymization, Anonymization and Data Masking

# COMMAND ----------

import logging,re
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# COMMAND ----------


def read_from_mount(mnt_path, format="csv", **options):
    try:
        # Read file from mnt path
        df = spark.read.format(format) \
            .option("header", "true") \
            .load(mnt_path, **options)
        return df
    except Exception as e:
        logger.error(f"Error reading file from mnt path: {mnt_path}")
        logger.exception(e)
        raise

# COMMAND ----------

account_name = "123"
account_key = "==567"
container_name = "poc-container"

spark.conf.set(
    f"fs.azure.account.key.{account_name}.blob.core.windows.net",
    account_key
)

files = dbutils.fs.ls(f"wasbs://{container_name}@{account_name}.blob.core.windows.net/")

def read_from_mount(mnt_path, format="csv", **options):
    try:
        # Read file from mnt path
        df = spark.read.format(format) \
            .option("header", "true") \
            .option("delimiter", options.get("delimiter", ",")) \
            .option("inferSchema", options.get("inferSchema", "true")) \
            .load(mnt_path)
        return df
    except Exception as e:
        raise e

for file_info in files:
    file_path = file_info.path
    df = read_from_mount(file_path, format="csv", delimiter=",", inferSchema=True)
    display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ![my_test_image](/files/gdpr_demo.png)

# COMMAND ----------

# MAGIC %md
# MAGIC **Psedonymize the email address**
# MAGIC
# MAGIC > _**`Pseudonymization is a data management and de-identification procedure by which personally identifiable information fields within a data record are replaced by one or more artificial identifiers, or pseudonyms`**_
# MAGIC
# MAGIC **_`Pseudonymization is one way to comply with the European Union's new General Data Protection Regulation (GDPR) demands for secure data storage of personal information`_**
# MAGIC
# MAGIC Here we are considering that email address is unquiley identify the customers, and hence Pseudo key will uniquely identify the customers as well.
# MAGIC
# MAGIC **write the customer table [default.raw_customer_data] into the delta lake**

# COMMAND ----------

import pyspark.sql.functions as F
df = df.withColumn("customer_pseudo_id", F.sha2(F.col("email"), 256))

df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable("default.raw_customer_data")

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC **Why & What is sha?**
# MAGIC
# MAGIC _SHA stands for Secure Hash Algorithm, a family of cryptographic functions that create unique hashes for data and certificate files_
# MAGIC
# MAGIC **How it Works?**
# MAGIC
# MAGIC _SHA uses a hash function to transform data into a fixed-size string that's nearly **impossible to reverse**. The hash function uses bitwise operations, modular additions, and compression functions_

# COMMAND ----------

# MAGIC %sql
# MAGIC select ID, Email, customer_pseudo_id from default.raw_customer_data limit 5

# COMMAND ----------

# MAGIC %md
# MAGIC **Data Masking - Generating the Cryptographic Key**
# MAGIC
# MAGIC Data masking ensures employees can perform their duties without seeing data they are not authorized to view. Faster, safer test data. Masked data retains the integrity and quality needed for testing without compromising the actual data.

# COMMAND ----------

from cryptography.fernet import Fernet
key = Fernet.generate_key()

# COMMAND ----------

# creating the user defined function to create the encryption key 
def generate_encrypt_key():
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    return key.decode("utf-8")
spark.udf.register("generate_key_using_Fernet", generate_encrypt_key)

# COMMAND ----------

# MAGIC %md
# MAGIC deafult.Encryption_key table keep the mapping between the customer ID and encryption keys

# COMMAND ----------

import pyspark.sql.functions as F
from pyspark.sql.types import StringType

generate_key_using_Fernet = udf(generate_encrypt_key, StringType())
df_distinct_record = spark.sql('''select distinct ID from default.raw_customer_data''')
df_distinct_record = df_distinct_record.withColumn("encryption_key", F.lit(generate_key_using_Fernet()))

df_distinct_record.write.format("delta").mode("overwrite").saveAsTable("default.encryption_keys")

# COMMAND ----------

# MAGIC %sql
# MAGIC select * from default.encryption_keys limit 5

# COMMAND ----------

# MAGIC %md
# MAGIC # `created the spark UDF to encrypt and decrypt the column.`

# COMMAND ----------

# Define Encrypt User Defined Function 
def encrypt_val(clear_text,MASTER_KEY):
    from cryptography.fernet import Fernet
    f = Fernet(MASTER_KEY)
    clear_text_b=bytes(clear_text, 'utf-8')
    cipher_text = f.encrypt(clear_text_b)
    cipher_text = str(cipher_text.decode('ascii'))
    return cipher_text

# Define decrypt user defined function 
def decrypt_val(cipher_text,MASTER_KEY):
    from cryptography.fernet import Fernet
    f = Fernet(MASTER_KEY)
    clear_val=f.decrypt(cipher_text.encode()).decode()
    return clear_val
spark.udf.register("decrypt_val", decrypt_val)
     

# COMMAND ----------

# MAGIC %md
# MAGIC Encryption ==> we are going to encrypt the column Email.

# COMMAND ----------


from pyspark.sql.functions import udf, lit, md5, col
from pyspark.sql.types import StringType
 
# Register UDF's
encrypt = udf(encrypt_val, StringType())
decrypt = udf(decrypt_val, StringType())
 
 
# Encrypt the data 
df = spark.sql('''select a.*,e.encryption_key from default.raw_customer_data as a 
inner join default.encryption_keys as e on e.ID=a.ID''')
encrypted = df.withColumn("EMAIL", encrypt("EMAIL", col("encryption_Key"))).drop("encryption_Key")
# display(encrypted.limit(10))
 
#Save encrypted data 
encrypted.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable("default.raw_customer_data")

# COMMAND ----------

# MAGIC %md
# MAGIC Masked Data

# COMMAND ----------

# MAGIC %sql
# MAGIC select ID, Email, customer_pseudo_id from default.raw_customer_data limit 5;

# COMMAND ----------

# MAGIC %md
# MAGIC Decrypt the data

# COMMAND ----------

encrypted = spark.sql('''select a.*,e.encryption_key from default.raw_customer_data as a 
inner join default.encryption_keys as e on e.ID=a.ID''')
decrypted = encrypted.withColumn("EMAIL", decrypt("EMAIL",(col("encryption_Key")))).drop("encryption_Key")
display(decrypted.select("ID", "EMAIL","customer_pseudo_id" ).limit(5))

# COMMAND ----------

# MAGIC %sql
# MAGIC select a.ID, decrypt_val(a.EMAIL,e.encryption_Key) as email, a.customer_pseudo_id
# MAGIC from default.raw_customer_data as a 
# MAGIC inner join default.encryption_keys as e on e.ID=a.ID
# MAGIC limit 5

# COMMAND ----------

# MAGIC %md
# MAGIC # **Anonymization Demo**

# COMMAND ----------

# MAGIC %sh pip install Faker unicodecsv

# COMMAND ----------

# MAGIC %pip
# MAGIC !pip install faker
# MAGIC from faker import Faker
# MAGIC import pyspark.sql.functions as F
# MAGIC from pyspark.sql.types import StringType

# COMMAND ----------

def anonymize_rows(rows):
    """
    Rows is an iterable of dictionaries that contain name, email, ssn, and phone_number fields that need to be anonymized.
    """
    from faker import Faker
    from collections import defaultdict

    # Load faker
    faker = Faker()

    # Create mappings of names, emails, social security numbers, and phone numbers to faked names & emails.
    names = defaultdict(faker.name)
    emails = defaultdict(faker.email)
    ssns = defaultdict(faker.ssn)
    phone_numbers = defaultdict(faker.phone_number)

    # Iterate over the rows from the file and yield anonymized rows.
    for row in rows:
        # Replace name, email, ssn, and phone_number fields with faked fields if they exist.
        if "NAME_" in row:
            row["NAME_"] = names[row["NAME_"]]
        if "EMAIL" in row:
            row["EMAIL"] = emails[row["EMAIL"]]
        if "TCNUMBER" in row:
            row["TCNUMBER"] = ssns[row["TCNUMBER"]]
        if "TELNR" in row:
            row["TELNR"] = phone_numbers[row["TELNR"]]

        # Yield the row back to the caller
        yield row

# Iterate through the files and read each one as a DataFrame
for file_info in files:
    file_path = file_info.path
    df = read_from_mount(file_path, format="csv", delimiter=",", inferSchema=True)
    
    # Convert DataFrame to Pandas DataFrame
    pdf = df.toPandas()
    
    # Anonymize the rows
    anonymized_rows = list(anonymize_rows(pdf.to_dict(orient="records")))
    
    # Convert back to Spark DataFrame
    anonymized_df = spark.createDataFrame(anonymized_rows, schema=df.schema)
    
    # Display the anonymized DataFrame
    display(anonymized_df)D

# COMMAND ----------

# Step 1: Display the Original DataFrame
display(df.select("ID", "NAME_", "EMAIL", "TCNUMBER", "TELNR").limit(5))

# Step 2: Display the Anonymized DataFrame
display(anonymized_df.select("ID", "NAME_", "EMAIL", "TCNUMBER", "TELNR").limit(5))

# Step 3: Join and Compare
comparison_df = df.alias("original").join(
    anonymized_df.alias("anonymized"),
    on="ID",
    how="inner"
).select(
    "ID",
    F.col("original.NAME_").alias("Original_NAME_"),
    F.col("anonymized.NAME_").alias("Anonymized_NAME_"),
    F.col("original.EMAIL").alias("Original_EMAIL"),
    F.col("anonymized.EMAIL").alias("Anonymized_EMAIL"),
    F.col("original.TCNUMBER").alias("Original_TCNUMBER"),
    F.col("anonymized.TCNUMBER").alias("Anonymized_TCNUMBER"),
    F.col("original.TELNR").alias("Original_TELNR"),
    F.col("anonymized.TELNR").alias("Anonymized_TELNR")
)

# Display the comparison DataFrame
display(comparison_df.limit(10))

# COMMAND ----------

def anonymize_rows(rows):
    """
    Rows is an iterable of dictionaries that contain name, email, ssn, and phone_number fields that need to be anonymized.
    """
    from faker import Faker
    from collections import defaultdict

    # Load faker
    faker = Faker()

    # Create mappings of names, emails, social security numbers, and phone numbers to faked names & emails.
    names = defaultdict(faker.name)
    emails = defaultdict(faker.email)
    ssns = defaultdict(faker.ssn)
    phone_numbers = defaultdict(faker.phone_number)

    # Iterate over the rows from the file and yield anonymized rows.
    for row in rows:
        # Replace name, email, ssn, and phone_number fields with faked fields if they exist.
        if "NAME_" in row:
            row["Original_NAME_"] = row["NAME_"]
            row["NAME_"] = names[row["NAME_"]]
        if "EMAIL" in row:
            row["Original_EMAIL"] = row["EMAIL"]
            row["EMAIL"] = emails[row["EMAIL"]]
        if "TCNUMBER" in row:
            row["Original_TCNUMBER"] = row["TCNUMBER"]
            row["TCNUMBER"] = ssns[row["TCNUMBER"]]
        if "TELNR" in row:
            row["Original_TELNR"] = row["TELNR"]
            row["TELNR"] = phone_numbers[row["TELNR"]]

        # Yield the row back to the caller
        yield row

# Iterate through the files and read each one as a DataFrame
for file_info in files:
    file_path = file_info.path
    df = read_from_mount(file_path, format="csv", delimiter=",", inferSchema=True)
    
    # Convert DataFrame to Pandas DataFrame
    pdf = df.toPandas()
    
    # Anonymize the rows
    anonymized_rows = list(anonymize_rows(pdf.to_dict(orient="records")))
    
    # Convert back to Spark DataFrame
    anonymized_df = spark.createDataFrame(anonymized_rows, schema=df.schema)
    
    # Display the anonymized DataFrame
    display(anonymized_df)

# COMMAND ----------

# Step 1: Display the Original DataFrame
display(df.select("ID", "NAME_", "EMAIL", "TCNUMBER", "TELNR").limit(5))

# Step 2: Display the Anonymized DataFrame
display(anonymized_df.select("ID", "NAME_", "EMAIL", "TCNUMBER", "TELNR").limit(5))

# Step 3: Join and Compare
comparison_df = df.alias("original").join(
    anonymized_df.alias("anonymized"),
    on="ID",
    how="inner"
).select(
    "ID",
    F.col("original.NAME_").alias("Original_NAME_"),
    F.col("anonymized.NAME_").alias("Anonymized_NAME_"),
    F.col("original.EMAIL").alias("Original_EMAIL"),
    F.col("anonymized.EMAIL").alias("Anonymized_EMAIL"),
    F.col("original.TCNUMBER").alias("Original_TCNUMBER"),
    F.col("anonymized.TCNUMBER").alias("Anonymized_TCNUMBER"),
    F.col("original.TELNR").alias("Original_TELNR"),
    F.col("anonymized.TELNR").alias("Anonymized_TELNR")
)

# Display the comparison DataFrame
display(comparison_df.limit(10))