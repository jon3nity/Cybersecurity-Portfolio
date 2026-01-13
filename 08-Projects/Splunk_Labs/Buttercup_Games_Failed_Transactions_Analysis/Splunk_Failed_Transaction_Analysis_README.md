# Buttercup Games Failed Transaction Analysis Dashboard

## Project Overview

This project demonstrates advanced SIEM analysis using Splunk Enterprise to investigate server failures impacting business. The analysis examines failed e-commerce transactions at Buttercup Games, analyzing revenue loss, identifying occurence patterns, determining root causes, and providing actionable recommendations for infrastructure improvements. This work showcases skills directly applicable to SOC Analyst, Security Analyst, and Junior Security Engineer roles in cybersecurity.

The dashboard provides organizational level visibility into server capacity issues while offering technical diagnostic capabilities for IT Operations teams. By combining business impact analysis with technical root cause investigation, this project demonstrates the dual perspective required in modern cybersecurity roles where analysts must communicate effectively with both technical and business stakeholders.

## Business Context

Buttercup Games experienced recurring server downtime affecting their e-commerce platform. The Director of Sales requested analysis to understand how these technical failures impacted revenue. This scenario mirrors real-world incident response where security and operations teams must access business impact while diagnosing technical root causes.

The analysis revealed server capacity constraints during peak traffic periods, resulted in revenue loss, with 503 Service Unavailable errors accounting for 58% of the transaction failures. This finding enabled infrastructure planning and capacity budgeting based on the data.

## Technical Implementation

### Data Sources
- **Sourcetype**: access_combined_wcookie (Apache web server logs)
- **Index**: main
- **Time Range**: December 21-31, 2025 (historical analysis)
- **Event Volume**: 26,250 total events analyzed
- **Failed Transactions**: 2,565 purchase attempts with status!=200

### Lookup Enrichment
The external lookup table (prices.csv), which has product pricing information, was used to determine real revenue impact. The lookup enrichment demonstrates my understanding of search-time field operations versus indexed fields, a key difference for effective SIEM query optimization.

Key fields from lookup:
- productId (join key)
- product_name (human-readable product identifier)
- price (unit price for revenue calculation)

### Dashboard Architecture

**Panel 1: Top 10 Products by Lost Revenue**
```spl
sourcetype="access_combined_wcookie" status!=200 action=purchase 
| lookup prices.csv productId OUTPUT product_name price
| stats count by product_name, price
| eval lost_revenue = count * price
| sort -lost_revenue
| head 10
| fields product_name lost_revenue
```

Visualization: 📊 Horizontal bar chart with formatted currency values.

Business Value: Identifies which products suffered most from server failures, enabling targeted inventory and marketing compensation strategies

**Panel 2: Web Application Failures Over Time (Hourly)**
```spl
sourcetype="access_combined_wcookie" status!=200 | timechart count span=1h
```

Visualization: 📈 Line chart showing failure rate trends | 
Key Finding: During peak traffic hours (evenings/nights), failure rates fluctuate regularly between (100–200 fail/hour) with occasional large spikes of (250–300/hour).

Technical Note: This panel intentionally excludes action=purchase filter to capture all HTTP errors across the application, providing broader infrastructure health visibility than just transaction failures.

**Panel 3: Failed Purchase Errors by HTTP Status Code**
```spl
sourcetype="access_combined_wcookie" status!=200 action=purchase 
| stats count by status
| sort -count
```

Visualization: 🕘 Pie chart showing error distribution
Critical Discovery: 503 errors (Service Unavailable) accounted for 1,498 of 2,565 failures (58.4%),  indicating server capacity constraints rather than application bugs or network issues.

Status Code Breakdown:
- 503 Service Unavailable: 1,498 (58.4%) - Server overload
- 408 Request Timeout: 279 (10.9%) - Slow server response
- 400 Bad Request: 185 (7.2%) - Client errors
- Other 4xx/5xx errors: Remaining distribution

**Panel 4: Total Lost Revenue**
```spl
sourcetype="access_combined_wcookie" status!=200 action=purchase 
| lookup prices.csv productId OUTPUT product_name price
| stats count by product_name, price
| eval lost_revenue = count * price
| stats sum(lost_revenue) as "Total Lost Revenue"
| eval "Total Lost Revenue" = round('Total Lost Revenue')
```

Visualization: 3️⃣ Single value display with numeric formatting
Executive Impact: EUR 36,794 in revenue loss was discovered during the analysis period
Technical Note: Rounded the decimal numbers to whole integers to fix accuracy problems when multiplying decimal currency values.

## Key Discoveries and Learning Outcomes

### Search-Time vs Indexed Field Operations
Understood and showed that lookup enrichment happens at search time rather than index time. Fields entered using lookup commands only show up in search results and must be reapplied in subsequent searches. This distinction is critical for query optimization and understanding why certain fields appear or disappear between searches.

### Command Choice Comparisons: top vs stats+eval+sort
Analyzed the difference between using the top command (quick frequency analysis) versus the more flexible stats+eval+sort+head pipeline. The 'top' command cannot perform calculations like revenue multiplication, making the longer pipeline necessary when aggregations require computed fields. This demonstrates understanding of when to use convenience commands versus building custom aggregation logic.

### HTTP Status Code Analysis for Root Cause Determination
Applied systematic diagnostic method by filtering  error types to distinguish between client-side issues (4xx), server-side failures (5xx), and redirects (3xx). The dominance of 503 errors shows infrastructure capacity problems rather than application defects, guiding the solution strategy toward scaling solutions instead of code debugging.

### Dashboard Design for Multi-Stakeholder Audiences
Structured the dashboard to serve both executive and technical audiences simultaneously. Single value metrics provide immediate business impact visibility for leadership, while detailed technical berakdowns support IT Operations troubleshooting. Panel descriptions and clear labeling ensure non-technical stakeholders can interpret findings without assistance.

### Error Pattern Recognition
Identified link between failure rates and peak traffic periods through time-series analysis. The consistent hourly baseline with predictable spikes indicated capacity constraints rather than security threats. This pattern recognition skill is essential for distinguishing between random failures, sustained capacity issues, and potential security incidents like DDoS attacks.

## Business Impact and Recommendations

### Business Impact Calculations
- Total Revenue Loss: EUR 33,707.15 over 10-day analysis period
- Transaction Failure Rate: 8.9% of all purchase attempts
- Peak Product Impact: Grand Theft Scooter (EUR 8,367 lost)
- Root Cause: Server capacity insufficient for peak traffic loads

### Actionable Recommendations for IT Operations

**Immediate Actions:**
1. Implement auto-scaling infrastructure to handle baseline traffic during peak hours (6pm-midnight)
2. Configure load balancing to distribute requests across multiple application servers
3. Establish real-time monitoring alerts for sustained 503 error rates above threshold

**ROI Justification:**
With EUR 33,707 lost in 10 days, infrastructure improvements costing EUR 50,000-100,000 should achieve payback within 2-3 months while supporting business growth and improving customer experience.

## Skills Demonstrated for Cybersecurity

### Technical Capabilities
- Splunk SPL (Search Processing Language) query construction and optimization
- Data enrichment using external lookup implementation
- Field extraction and transformation using the 'eval' command
- Time-series analysis using timechart for pattern recognition
- Statistical aggregation using stats command with multiple grouping fields
- Dashboard design and visualization selection for effective data presentation

### Analytical Methodologies
- Hypothesis formation and actual testing (predicted 500 errors, data showed 503 dominance)
- Root cause analysis using systematic diagnostic approach
- Business impact calcaulation by combining technical metrics with financial data
- Temporal pattern recognition for distinguishing incident types
- Multi-perspective analysis benefiting both technical and business stakeholders

### Business Communication
- Executive summary presentation with clear ROI calculations
- Technical documentation suitable for IT Operations handover
- Selection and marking of visualizations suitable for stakeholders
- Actionable recommendation development with implementation priorities

## Repository Contents

### Installation Instructions

To import this dashboard into your Splunk environment:

1. Ensure you have Splunk Enterprise 8.0+ installed
2. Load the Buttercup Games tutorial data (included with Splunk)
3. Create and configure the prices.csv lookup table with product pricing data
4. Navigate to Dashboards > Create New Dashboard
5. Select "Source" mode and paste the contents of dashboard.json
6. Adjust time ranges as needed for your data set
7. Verify all panels render correctly with your data

Note: The dashboard expects the access_combined_wcookie sourcetype and prices.csv lookup to be configured. Adjust sourcetype names if your data uses different naming.

## Certification Relevance

This project directly applies concepts tested in the Splunk Core Certified User examination:

- Module 4: Basic Searching - Field-value pair filtering, boolean operators, comparison operators
- Module 6: Using Fields in Searches - Field selection, interesting fields, lookup enrichment
- Module 7: Search Fundamentals - Command piping, search pipeline optimization
- Module 8: Transforming Commands - stats, eval, sort, head, fields, rename commands
- Module 9: Creating Reports and Dashboards - Multi-panel dashboard design, visualization selection
- Module 10: Creating and Using Lookups - External lookup configuration, OUTPUT clause usage

## Tools and Technologies

- Splunk Enterprise 9.x (SIEM platform)
- SPL (Search Processing Language)
- CSV lookup tables for data enrichment
- Apache web server log analysis
- Dashboard Studio for visualization
- JSON for dashboard portability

## Future Enhancements

Potential extensions to demonstrate additional capabilities:

1. Implement scheduled searches with email alerting when failure rates exceed thresholds
2. Add geolocation analysis to identify if failures correlate with specific regions
3. Create comparison dashboard showing before/after metrics post-infrastructure improvements
4. Develop predictive analytics to forecast when capacity constraints will occur
5. Integrate with ticketing systems for automated incident creation

## Author

Chinedu John Onyekachi

## License

This project is created for educational and portfolio demonstration purposes. The Buttercup Games dataset is provided by Splunk Inc. for training purposes.
