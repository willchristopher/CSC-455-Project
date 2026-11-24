# Phishing Website Detection System

Will Christopher and Zach Walters

## Summary

We built a Python program that checks a URL for signs of phishing. You paste an address into a Tkinter window, and the program shows the hostname, the site it points to, and a score from our model. The program reads the link as text and runs locally.

## Security Problem

Phishing pages can look like a service people trust and trick them into entering their credentials. An address like `www.google.com.example.org` can make the page look familiar even though the destination is `example.org`. HTTPS protects the connection to the destination, which can still be a phishing site.

## Design and Implementation

We followed the Tkinter example from class for the interface. When someone selects **Check URL**, `app.py` sends the text to `detector.py`. The detector reads the hostname, path, and query and turns them into 18 numbers. These include things like the length of the hostname, how many digits and subdomains it has, and the number of query parameters. We use the Public Suffix List to identify the site in addresses like `help.example.co.uk`, where the site is `example.co.uk`.

We decided to use a decision tree trained with scikit-learn. The tree learns which features and cutoffs best separate the examples at each step. When we check a URL, we follow those comparisons until we reach a final group. The score is the weighted share of phishing links in that group during training. A score of 0.4 or higher flags the URL. The app loads the tree from `data/model.json`.

## Training and Testing

We used labeled legitimate and phishing links from PhiUSIIL and URL-Phish v2. We split by site, so URLs from the same site stay together across both sources. We used 235,311 URLs to fit the models we compared and another 50,416 to check which settings worked better. Based on validation, we chose a single tree with at most 10 splits per path and a 0.4 cutoff. We refit it on all 285,727 training and validation URLs and used the original 66,660 test URLs to compare it with logistic regression.

During training, we gave each of the four dataset and label combinations the same total weight and required at least 100 training examples in each final group. We treat a homepage address with or without a trailing slash the same way. We left HTTP versus HTTPS out because the two datasets differ in how often legitimate links use HTTPS.

We ran unit tests for parsing, scoring, and counting errors. We then ran the saved model on the held-out URLs. A false positive is a legitimate link we flagged. A false negative is a phishing link we missed. Eight phishing URLs had invalid or unsupported addresses and were excluded before splitting.

## Results

Across both test sets, accuracy increased from 82.55% with logistic regression to 87.21% with the decision tree. The tree flagged 2,635 of 46,538 legitimate links** (5.66%), down from 5,194 (11.16%). It missed 5,893 of 20,122 phishing links (29.29%), down from 6,437 (31.99%).

On PhiUSIIL, accuracy was 85.14%, with 859 false positives (3.22%) and 5,778 false negatives (32.14%). The tree caught 569 more phishing links and raised 511 more false alarms. On URL-Phish v2, accuracy rose from 77.56% to 91.40%, with 1,776 false positives (8.95%) and 115 false negatives (5.36%). The tree raised 3,070 fewer false alarms there and missed 25 more phishing links.

## Limitations

The model can only see the address. Of the 5,778 phishing links the tree missed in PhiUSIIL, 5,567 had no path segments. A short URL on a compromised site can look like an ordinary homepage. The tree also scored `https://gooogle.com` at about 0.295, below our cutoff, because it scores measurements such as hostname length and digit count. A test with newer links from a third source would tell us more about how well it works outside these datasets.

## Conclusion

The decision tree reduced both types of errors across the combined tests. We would use the score and the displayed site as a prompt to verify the destination.

## Running the Program

Use Python 3.11 or newer with Tkinter. From the project folder, run `python -m pip install -r requirements.txt` and then `python app.py`. For the demo, paste `https://www.example.org/` and then `http://confirm-account-119.example.net/signin/check/8?session=abc` into the app to show both results. These are example addresses for the demo.

Run `python -m unittest` for the unit tests. To retrain and print the held-out results, download the two CSVs linked below, install `requirements-train.txt` with pip, and run `python train.py "path/to/PhiUSIIL_Phishing_URL_Dataset.csv" "path/to/url-phish-v2.csv"`. To repeat the evaluation alone, run `python evaluate.py "path/to/dataset.csv" --held-out`. Add `--phishing-label 1` for URL-Phish v2. For a new labeled CSV that was never used in training, leave off `--held-out` to test every valid row.

## References

We used scikit-learn for training and the Public Suffix List for identifying sites. We trained and tested on Prasad and Chandra’s *PhiUSIIL Phishing URL (Website)* and Dam Minh and Tran Cong’s *URL-Phish*, version 2. [Decision tree](https://scikit-learn.org/stable/modules/generated/sklearn.tree.DecisionTreeClassifier.html) · [Public Suffix List](https://publicsuffix.org/list/) · [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) · [URL-Phish v2](https://data.mendeley.com/datasets/65z9twcx3r/2)

## AI Acknowledgment

AI was used for brainstorming an approach to this project. When thinking about how we would build a machine-learning model, we asked Google Gemini about ways of going about this and ultimately landed on what we have today. It guided us by having references of what setting up a decision tree would look like in Python, and the use of IntelliSense/Copilot within VS Code was used as we were typing the code.
