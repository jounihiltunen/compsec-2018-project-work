#!/usr/bin/python

import pandas as pd
import argparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import ExtraTreesClassifier
import numpy as np
from sklearn.metrics import confusion_matrix, zero_one_loss
from sklearn.feature_selection import SelectPercentile
from matplotlib import pyplot as plt
import os
import cPickle as pickle

parser = argparse.ArgumentParser(description='Extra tree classifier')
parser.add_argument("-i", "--input", required=True, help="Input data file in csv format")
parser.add_argument('--feature', dest='feature', action='store_true', help="Print the feature ranking.")
parser.add_argument("-p", "--persist", required=False, default="", help="File name to store pickle file. Disabled by default")
parser.add_argument('-t', required=False, default=-1, type=int, dest='threshold', help='Feature selection threshold. Default -1 (disabled)')
parser.set_defaults(feature=False)

args = parser.parse_args()

if args.persist is not "" and os.path.exists(args.persist):
    print("[!] Pickle file exists. Abort.")
    exit()

df = pd.read_csv(args.input,index_col='file_hash')

# Check if there are NaNs in the dataset
if df.isnull().any().any():
    print("[*] Filling Nan with 0")
    df.fillna(value=0,inplace=True)

# Create training and test sets
y = df['positives']
x = df.drop(columns=['positives'])

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)

if args.threshold > 0:
    # Remove non-informative features (noise)
    select = SelectPercentile(percentile=50)
    select.fit(x_train,y_train)
    x_train_selected = select.transform(x_train)
    x_test_selected = select.transform(x_test)

# Train classifier
# Build a forest and compute the feature importances
clf = ExtraTreesClassifier(n_estimators=250,
                              random_state=0)
clf.fit(x_train,y_train)
# Test classifier
print("Score: {:.3f}".format(clf.score(x_test,y_test)))
# Run prediction
pred = clf.predict(x_test)

if args.threshold > 0:
    # Try with selected features
    clf.fit(x_train_selected,y_train)
    # Test classifier
    print("Score (selected): {:.3f}".format(clf.score(x_test_selected,y_test)))
    # Run prediction
    pred_selected = clf.predict(x_test_selected)


# No need to plot binary classifier
if y.max() > 1:
    plt.scatter(y_test, pred, c='b', marker='x', label='Full')
    if args.threshold > 0:
        plt.scatter(y_test, pred_selected, c='r', marker='s', label='Selected')
    plt.xlabel('True values')
    plt.ylabel('Predictions')
    plt.show()

if args.feature:
    importances = clf.feature_importances_
    std = np.std([tree.feature_importances_ for tree in clf.estimators_],
             axis=0)
    indices = np.argsort(importances)[::-1]

    # Print the feature ranking
    print("Feature ranking:")

    for f in range(x.shape[1]):
        print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))

    # Plot the feature importances of the forest
    if 0:
        plt.figure()
        plt.title("Feature importances")
        plt.bar(range(x.shape[1]), importances[indices],
            color="r", yerr=std[indices], align="center")
        plt.xticks(range(x.shape[1]), indices)
        plt.xlim([-1, x.shape[1]])
        plt.show()

# tn, fp, fn, tp
print("[*] tn, fp, fn, tp: {}".format(confusion_matrix(y_test,pred).ravel()))
if args.threshold > 0:
    print("[*] tn, fp, fn, tp (selected): {}".format(confusion_matrix(y_test,pred_selected).ravel()))
# fraction of misclassifications'
print("[*] Fraction of misclassifications: {}".format(zero_one_loss(y_test,pred)))
if args.threshold > 0:
    print("[*] Fraction of misclassifications (selected): {}".format(zero_one_loss(y_test,pred_selected)))

if args.persist is not "":
    print("Saving persist data.")
    pickle.dump(clf, open(args.persist,"wb"))
    with open(args.persist+".x_test.csv", "w") as f:
        x_test.to_csv(f)
    with open(args.persist+".y_test.csv", "w") as f:
        y_test.to_csv(f)
    with open(args.persist+".x_train.csv", "w") as f:
        x_train.to_csv(f)
    with open(args.persist+".y_train.csv", "w") as f:
        y_train.to_csv(f)


