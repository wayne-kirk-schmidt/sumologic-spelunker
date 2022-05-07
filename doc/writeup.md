Business Background
===================

Migrating between platforms can be challenging, especially if you have an platform developed over time. 

For many Splunk users who want to use the power of Sumo Logic, migrating content and configuration can be a daunting task. Where do you start?Are there any areas to be especially careful of? Is there a way to start mapping out the institutional knowledge you have built up?

Business Challenge
==================

Our goal is to be able to build up a map of the institutional wisdom built up in another application, so we can best understand how to migrate from another system to Sumo Logic.

We need to make sure we can have the data broken down by user activity, content configuration, collection setup, and all of the settings enabled and used within the platform.

We need to be able to identify the data by both system and time, since we may have multiple systems as well as multiple imports.

Business Cases
==============

Here are a sample of questions you want to have answers for to help your teams. Each of these questions deals with change.

* What are uses doing with the existing system?

* What questions are they looking to answer?

* How are they answering these questions ( what features are being used )?

* How is the content and applications within the platform structured?

* What is the level of queries being used? What are involved and what are more simple?

Business Solution
=================

Our solution using "Sumo on Sumo", feeding Sumo Logic data about how people are working with Sumo Logic to help your business.

And, best of all, this can be done in several easy steps:

- Create a HTTPS collector using these [steps](https://help.sumologic.com/03Send-Data/Hosted-Collectors).

- Create a HTTPS source using these [steps](https://help.sumologic.com/03Send-Data/Sources/02Sources-for-Hosted-Collectors).

- Obtain a Splunk Diag File using these [steps](https://docs.splunk.com/Documentation/Splunk/8.2.6/Troubleshooting/Generateadiag#:~:text=To%20generate%20and%20view%20diags,Click%20Settings%20%3E%20Instrumentation)

- Set up the ingest script following the [readme](../README.md).

- Run the script! Now you can check the source categories for the data you want to see.

Business Benefits
=================

The result? We can show you your content, your queries, your user activity to streamline your ability to migrate from Splunk to Sumo Logic.

You and Sumo Logic; discover the possible!
