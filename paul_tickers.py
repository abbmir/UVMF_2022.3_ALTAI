from pprint import pprint
##!<import pandas as pd
##!<import matplotlib.pyplot as plt
##!<from datetime import datetime
# Raw Package
import numpy as np
import pandas as pd

#Data Source
import yfinance as yf
#Data viz
import plotly.graph_objs as go
ticker_list = ['TTOO','NNDM' ,'RVP' ,'IPWR' ,'OPTT' ,'LTBR' ,'BIOC' ,'OCX' ,'SMED' ,'RWLK', 'CLSK' ,'LTRX' ,'MARA' ,'SQNS' ,'ONVO' ,'PXLW' ,
               'HYRE' ,'WWR','SLGG','ICCC' ,'VYNT' ,'URG' ,'IDXG' ,'BOXL' ,'WISA' ,'PLUR' ,'WATT' ,'MOSYX' ,'APDN' , 'AQMS' ,'TRT' ,
               'GMDA' ,'AFIB' ,'SCYX' ,'WRAP' ,'EOSE','VGFCQ',
               'DTIL','ALIM','SQNS','RMBL','AMSC','HGEN', 'INGN','VSTM','KSCP','HUBC', 'HYREQ', 'STXS', 'APRN','EKSO','ITI']
#yf.download(tickers="BTC-USD",period="22 last hours",interval="15 mins")
#data = yf.download(tickers='BTC-USD', period = '60m', interval = '1m')
#data = yf.download(tickers = ticker_list ,period='1d', start='2023-07-10')
data = [
        yf.download(tickers = 'TTOO' ,period='1d', start='2020-05-05'),
        yf.download(tickers = 'NNDM' ,period='1d', start='2020-06-02'),
        yf.download(tickers = 'RVP' ,period='1d', start='2020-06-02'),
        yf.download(tickers = 'IPWR' ,period='1d', start='2020-06-10'),
        yf.download(tickers = 'OPTT' ,period='1d', start='2020-06-16'),
        yf.download(tickers = 'LTBR' ,period='1d', start='2020-06-16'),
        yf.download(tickers = 'BIOC' ,period='1d', start='2020-06-16'),
        yf.download(tickers = 'OCX' ,period='1d', start='2020-08-03'),
        #yf.download(tickers = 'SMED' ,period='1d', start='2020-08-07'), ACQUISITION!!
        yf.download(tickers = 'RWLK' ,period='1d', start='2020-08-25'),
        yf.download(tickers = 'CLSK' ,period='1d', start='2020-09-08'),
        yf.download(tickers = 'LTRX' ,period='1d', start='2020-09-23'),
        yf.download(tickers = 'MARA' ,period='1d', start='2020-09-25'),
        yf.download(tickers = 'SQNS' ,period='1d', start='2020-10-20'),
        yf.download(tickers = 'ONVO' ,period='1d', start='2020-10-21'),
        yf.download(tickers = 'PXLW' ,period='1d', start='2020-11-06'),
        yf.download(tickers = 'HYREQ' ,period='1d', start='2020-11-30'), ## sell on 3/9/23
        yf.download(tickers = 'WWR' ,period='1d', start='2020-01-20'), 
        yf.download(tickers = 'SLGG' ,period='1d', start='2021-01-12'),
        yf.download(tickers = 'ICCC' ,period='1d', start='2021-01-29'),#
        yf.download(tickers = 'VYNT' ,period='1d', start='2021-02-25'),
        yf.download(tickers = 'URG' ,period='1d', start='2021-03-15'),
        yf.download(tickers = 'IDXG' ,period='1d', start='2021-04-01'),
        yf.download(tickers = 'BOXL' ,period='1d', start='2021-04-26'),
        yf.download(tickers = 'WISA' ,period='1d', start='2021-05-12'),
        yf.download(tickers = 'PLUR' ,period='1d', start='2021-06-04'),
        yf.download(tickers = 'WATT' ,period='1d', start='2021-07-30'),
        yf.download(tickers = 'MOSYX' ,period='1d', start='2021-08-04'),
        yf.download(tickers = 'APDN' ,period='1d', start='2021-10-12'),
        #yf.download(tickers = 'CLXT' ,period='1d', start='2021-10-26'), Delisted
        yf.download(tickers = 'AQMS' ,period='1d', start='2021-12-06'),
        yf.download(tickers = 'TRT' ,period='1d', start='2021-12-22'),
        yf.download(tickers = 'GMDA' ,period='1d', start='2022-03-01'),
        yf.download(tickers = 'AFIB' ,period='1d', start='2022-03-09'),
        yf.download(tickers = 'SCYX' ,period='1d', start='2022-03-16'),
        yf.download(tickers = 'WRAP' ,period='1d', start='2022-04-18'),
        yf.download(tickers = 'EOSE' ,period='1d', start='2022-03-17'),##
        yf.download(tickers = 'VGFCQ' ,period='1d', start='2022-06-08'),

        yf.download(tickers = 'DTIL' ,period='1d', start='2023-08-18'),
        yf.download(tickers = 'ALIM' ,period='1d', start='2023-08-15'),
        yf.download(tickers = 'SQNS' ,period='1d', start='2023-08-07'),
        yf.download(tickers = 'RMBL' ,period='1d', start='2023-08-01'),
        yf.download(tickers = 'AMSC' ,period='1d', start='2023-07-27'),
        yf.download(tickers = 'HGEN' ,period='1d', start='2023-07-10'),
        yf.download(tickers = 'INGN' ,period='1d', start='2023-06-27'),
        yf.download(tickers = 'VSTM' ,period='1d', start='2023-06-20'),
        yf.download(tickers = 'KSCP' ,period='1d', start='2023-05-26'),
        yf.download(tickers = 'HUBC' ,period='1d', start='2023-03-20'),
        yf.download(tickers = 'HYREQ' ,period='1d', start='2023-03-09'),
        yf.download(tickers = 'STXS' ,period='1d', start='2023-02-17'),
        yf.download(tickers = 'APRN' ,period='1d', start='2023-02-03'),
        yf.download(tickers = 'EKSO' ,period='1d', start='2023-01-10'),
        yf.download(tickers = 'ITI' ,period='1d', start='2023-08-24'),
        
        ]
# n=0
# for line in data:
#     print(ticker_list[n],line)
#     n+=1

#fig = go.Figure(data = go.Candlestick(x = data[0].index, open = data[0]['Open'], high=data[0], low=data[0], close=data[0], name = 'market data'))
# fig = go.Figure()
# fig.add_trace(go.Candlestick(x = data[0].index, open = data[0]['Open'], high=data[0]['High'], low=data[0]['Low'], close=data[0]['Close'], name = 'HGEN' ))
# fig.add_traces(go.Candlestick(x = data[1].index, open = data[1]['Open'], high=data[1]['High'], low=data[1]['Low'], close=data[1]['Close'], name = 'INGN'))
# fig.add_traces(go.Candlestick(x = data[2].index, open = data[2]['Open'], high=data[2]['High'], low=data[2]['Low'], close=data[2]['Close'], name = 'VSTM'))
# fig.add_traces(go.Candlestick(x = data[3].index, open = data[3]['Open'], high=data[3]['High'], low=data[3]['Low'], close=data[3]['Close'], name = 'KSCP'))
# fig.add_traces(go.Candlestick(x = data[4].index, open = data[4]['Open'], high=data[4]['High'], low=data[4]['Low'], close=data[4]['Close'], name = 'VSTM'))
# fig.show()
fig = go.Figure()
for line, ticker in zip(data,ticker_list):
       # starting_price = line['Close'][0]  
        #ending_price = line['Close'][-1]   
    
        #if ending_price < starting_price:
        fig.add_trace(go.Candlestick(x = line.index, open = line['Open'], high=line['High'], low=line['Low'], close=line['Close'], name = ticker ))

fig.update_traces(selector=dict(name = 'INGN'), increasing_line=dict(color='blue'), increasing_fillcolor = 'blue', decreasing_line=dict(color='yellow'), decreasing_fillcolor = 'yellow')
fig.update_traces(selector=dict(name = 'VSTM'),  increasing_line=dict(color='magenta'),  increasing_fillcolor = 'magenta',   decreasing_line=dict(color='orange'), decreasing_fillcolor = 'orange')
fig.update_traces(selector=dict(name = 'KSCP'),  increasing_line=dict(color='cyan'),     increasing_fillcolor = 'cyan',      decreasing_line=dict(color='pink'),   decreasing_fillcolor = 'pink')
fig.update_traces(selector=dict(name = 'VSTM'),  increasing_line=dict(color='magenta'),  increasing_fillcolor = 'magenta',   decreasing_line=dict(color='orange'), decreasing_fillcolor = 'orange')
fig.update_traces(selector=dict(name = 'HUBC'),  increasing_line=dict(color='teal'),     increasing_fillcolor = 'teal',      decreasing_line=dict(color='coral'),  decreasing_fillcolor = 'coral')
fig.update_traces(selector=dict(name = 'HYREQ'), increasing_line=dict(color='lavender'), increasing_fillcolor = 'lavender',  decreasing_line=dict(color='crimson'),decreasing_fillcolor = 'crimson')
fig.update_traces(selector=dict(name = 'VGFCQ'), increasing_line=dict(color='turquoise'),increasing_fillcolor = 'turquoise', decreasing_line=dict(color='gold'),   decreasing_fillcolor = 'gold')
fig.update_traces(selector=dict(name = 'STXS'),  increasing_line=dict(color='aquamarine'),increasing_fillcolor = 'aquamarine',decreasing_line=dict(color='linen'),decreasing_fillcolor = 'linen')
fig.update_traces(selector=dict(name = 'APRN'),  increasing_line=dict(color='indigo'),   increasing_fillcolor = 'indigo',    decreasing_line=dict(color='firebrick'),  decreasing_fillcolor = 'firebrick')
                  


fig.update_layout(title="Candlestick Chart for Multiple Stocks",
                  xaxis_title="Date",
                  yaxis_title="Stock Price",
                  xaxis_rangeslider_visible=True)

fig.show()